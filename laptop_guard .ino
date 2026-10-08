/*
 * ============================================================
 *  Smart Laptop Anti-Theft & Intrusion Detection System
 *  Arduino Nano firmware
 * ============================================================
 *
 *  WIRING
 *  ------
 *  Reed switch ...... D2  <-> GND            (uses INPUT_PULLUP)
 *  White LED ........ D3  -> 220R -> LED -> GND
 *  Red LED .......... D4  -> 220R -> LED -> GND
 *  SIM800L TX ....... D10                    (Nano receives)
 *  SIM800L RX ....... D11 -> 1K -> [node] -> SIM800L RX
 *                                  [node] -> 2K -> GND   (voltage divider)
 *  SIM800L VCC ...... Li-ion battery 3.7-4.2V (+ 1000uF capacitor)
 *  SIM800L GND ...... common GND with the Nano
 *
 *  Reed logic: magnet near sensor (laptop closed) = LOW
 *              magnet away        (laptop open)   = HIGH
 *
 *  FLOW
 *  ----
 *  Lid opens (armed) -> white LED + SMS + Python asks for password
 *    correct password -> access allowed, red LED off
 *    wrong password   -> red LED + SMS (call after MAX_WRONG_ATTEMPTS)
 *    no password      -> alarm after LOGIN_TIMEOUT_MS
 *  Lid closes        -> everything resets, LEDs off
 *
 *  USB PROTOCOL (Arduino <-> Python, one line per message)
 *  --------------------------------------------------------
 *  Arduino -> Python : EVT:OPEN | EVT:FAIL:<n> | EVT:ALARM |
 *                      EVT:CLOSED | EVT:UNLOCK
 *  Python  -> Arduino: AUTH:OK | AUTH:FAIL | SYNC
 *
 *  SMS COMMANDS (accepted from OWNER_NUMBER only)
 *  ----------------------------------------------
 *  ARM | DISARM | STATUS | CALL
 * ============================================================
 */

#include <SoftwareSerial.h>

/* ===================== USER SETTINGS ===================== */
const char OWNER_NUMBER[] = "+966500000000";   // international format
const uint8_t MAX_WRONG_ATTEMPTS = 3;          // set to 1 = call on first mistake
const unsigned long LOGIN_TIMEOUT_MS = 30000UL; // time allowed to type password
const unsigned long CALL_DURATION_MS = 20000UL; // ring time before hang up
const unsigned long DEBOUNCE_MS = 50UL;

/* ========================== PINS ========================= */
const uint8_t PIN_REED      = 2;
const uint8_t PIN_LED_WHITE = 3;
const uint8_t PIN_LED_RED   = 4;
const uint8_t PIN_SIM_RX    = 10;  // Nano RX  <- SIM800L TX
const uint8_t PIN_SIM_TX    = 11;  // Nano TX  -> SIM800L RX (via divider)

SoftwareSerial sim(PIN_SIM_RX, PIN_SIM_TX);

/* ========================= STATE ========================= */
enum State : uint8_t { LID_CLOSED, WAITING_LOGIN, AUTHORIZED, ALARM };

State state = LID_CLOSED;
bool armed = true;
bool lidOpen = false;
uint8_t wrongAttempts = 0;
unsigned long openedAt = 0;

bool callActive = false;
unsigned long callStartedAt = 0;

/* ===================== LINE READING ====================== */
const uint8_t LINE_MAX = 100;
char usbBuf[LINE_MAX];
uint8_t usbLen = 0;
char simBuf[LINE_MAX];
uint8_t simLen = 0;

bool nextIsSmsBody = false;
bool senderIsOwner = false;

/* ------------------------------------------------------------
 * Reads characters without blocking. Returns true when a full
 * non-empty line is ready in buf.
 * ------------------------------------------------------------ */
bool readLine(Stream &port, char *buf, uint8_t &len) {
  while (port.available()) {
    char c = port.read();
    if (c == '\n') {
      buf[len] = '\0';
      bool hasText = (len > 0);
      len = 0;
      return hasText;
    }
    if (c != '\r' && len < LINE_MAX - 1) {
      buf[len++] = c;
    }
  }
  return false;
}

/* ======================= HELPERS ========================= */
void setLeds(bool white, bool red) {
  digitalWrite(PIN_LED_WHITE, white ? HIGH : LOW);
  digitalWrite(PIN_LED_RED, red ? HIGH : LOW);
}

const char *stateName() {
  switch (state) {
    case LID_CLOSED:    return "CLOSED";
    case WAITING_LOGIN: return "WAITING";
    case AUTHORIZED:    return "AUTHORIZED";
    case ALARM:         return "ALARM";
  }
  return "?";
}

/* ======================= SIM800L ========================= */
bool waitFor(char target, unsigned long timeoutMs) {
  unsigned long start = millis();
  while (millis() - start < timeoutMs) {
    while (sim.available()) {
      if (sim.read() == target) return true;
    }
  }
  return false;
}

void sendAt(const __FlashStringHelper *cmd) {
  sim.println(cmd);
  delay(400);
  while (sim.available()) sim.read();  // discard the reply
}

void initSim() {
  sim.begin(9600);
  delay(1000);
  sendAt(F("AT"));
  sendAt(F("ATE0"));               // echo off
  sendAt(F("AT+CMGF=1"));          // SMS text mode
  sendAt(F("AT+CNMI=2,2,0,0,0"));  // push new SMS straight to serial
  sendAt(F("AT+CMGD=1,4"));        // delete old stored messages
}

// SMS text must be plain English (GSM default charset)
void sendSms(const char *text) {
  sim.print(F("AT+CMGS=\""));
  sim.print(OWNER_NUMBER);
  sim.println('"');
  if (waitFor('>', 5000)) {
    sim.print(text);
    sim.write(26);          // Ctrl+Z = send
    waitFor('K', 15000);    // wait for "OK"
  } else {
    sim.write(27);          // ESC = cancel
  }
}

void makeCall() {
  sim.print(F("ATD"));
  sim.print(OWNER_NUMBER);
  sim.println(';');         // ';' = voice call
  callActive = true;
  callStartedAt = millis();
}

void checkCallTimeout() {
  if (callActive && millis() - callStartedAt > CALL_DURATION_MS) {
    sim.println(F("ATH"));  // hang up
    callActive = false;
  }
}

/* ======================= ALARM LOGIC ===================== */
void triggerAlarm(const char *reason) {
  state = ALARM;
  setLeds(true, true);
  Serial.println(F("EVT:ALARM"));
  sendSms(reason);
  makeCall();
}

void onWrongPassword() {
  wrongAttempts++;
  setLeds(true, true);
  Serial.print(F("EVT:FAIL:"));
  Serial.println(wrongAttempts);

  if (wrongAttempts >= MAX_WRONG_ATTEMPTS) {
    triggerAlarm("ALERT: too many wrong passwords on your laptop!");
  } else {
    char msg[60];
    snprintf(msg, sizeof(msg), "Wrong password attempt %d of %d.",
             wrongAttempts, MAX_WRONG_ATTEMPTS);
    sendSms(msg);
  }
}

void checkLoginTimeout() {
  if (state == WAITING_LOGIN && millis() - openedAt > LOGIN_TIMEOUT_MS) {
    triggerAlarm("ALERT: laptop opened and no password entered!");
  }
}

/* ===================== LID (REED SWITCH) ================= */
void onLidOpened() {
  setLeds(true, false);
  if (!armed) {
    state = AUTHORIZED;     // system disarmed: no password needed
    return;
  }
  state = WAITING_LOGIN;
  wrongAttempts = 0;
  openedAt = millis();
  Serial.println(F("EVT:OPEN"));
  sendSms("Your laptop was opened. Waiting for password.");
}

void onLidClosed() {
  state = LID_CLOSED;
  wrongAttempts = 0;
  setLeds(false, false);
  Serial.println(F("EVT:CLOSED"));
}

void checkLid() {
  static bool lastRaw = false;
  static unsigned long changedAt = 0;

  bool raw = (digitalRead(PIN_REED) == HIGH);   // HIGH = open
  if (raw != lastRaw) {
    lastRaw = raw;
    changedAt = millis();
  }
  // accept the change only after it stayed stable (debounce)
  if (millis() - changedAt > DEBOUNCE_MS && raw != lidOpen) {
    lidOpen = raw;
    if (lidOpen) onLidOpened();
    else         onLidClosed();
  }
}

/* ================= MESSAGES FROM PYTHON (USB) ============ */
void handleUsbLine(const char *line) {
  if (strcmp(line, "AUTH:OK") == 0) {
    if (state == WAITING_LOGIN) {
      state = AUTHORIZED;
      wrongAttempts = 0;
      setLeds(true, false);               // red off
    }
  } else if (strcmp(line, "AUTH:FAIL") == 0) {
    if (state == WAITING_LOGIN) onWrongPassword();
  } else if (strcmp(line, "SYNC") == 0) {
    // Python just started: tell it what screen to show
    if (state == WAITING_LOGIN) Serial.println(F("EVT:OPEN"));
    else if (state == ALARM)    Serial.println(F("EVT:ALARM"));
  }
}

/* ================== SMS COMMANDS FROM OWNER ============== */
void handleCommand(char *cmd) {
  size_t n = strlen(cmd);
  while (n > 0 && cmd[n - 1] == ' ') cmd[--n] = '\0';
  for (char *p = cmd; *p; p++) *p = toupper(*p);

  if (strcmp(cmd, "ARM") == 0) {
    armed = true;
    sendSms("System ARMED.");

  } else if (strcmp(cmd, "DISARM") == 0) {
    armed = false;
    if (state == WAITING_LOGIN || state == ALARM) {
      state = AUTHORIZED;
      setLeds(lidOpen, false);
      Serial.println(F("EVT:UNLOCK"));
    }
    sendSms("System DISARMED.");

  } else if (strcmp(cmd, "STATUS") == 0) {
    char msg[80];
    snprintf(msg, sizeof(msg), "Armed:%s Lid:%s State:%s",
             armed ? "YES" : "NO", lidOpen ? "OPEN" : "CLOSED", stateName());
    sendSms(msg);

  } else if (strcmp(cmd, "CALL") == 0) {
    makeCall();
  }
}

void handleSimLine(char *line) {
  if (nextIsSmsBody) {                       // line after +CMT = SMS text
    nextIsSmsBody = false;
    if (senderIsOwner) handleCommand(line);
    return;
  }
  if (strncmp(line, "+CMT:", 5) == 0) {      // new SMS header
    senderIsOwner = (strstr(line, OWNER_NUMBER) != NULL);
    nextIsSmsBody = true;
  }
}

/* ===================== SETUP / LOOP ====================== */
void setup() {
  pinMode(PIN_REED, INPUT_PULLUP);
  pinMode(PIN_LED_WHITE, OUTPUT);
  pinMode(PIN_LED_RED, OUTPUT);
  setLeds(false, false);

  Serial.begin(9600);
  initSim();
  Serial.println(F("EVT:READY"));
}

void loop() {
  checkLid();
  checkLoginTimeout();
  checkCallTimeout();

  if (readLine(Serial, usbBuf, usbLen)) handleUsbLine(usbBuf);
  if (readLine(sim, simBuf, simLen))    handleSimLine(simBuf);
}
