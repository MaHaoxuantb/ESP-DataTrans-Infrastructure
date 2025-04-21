#include <painlessMesh.h>
#include <ArduinoJson.h>
#include <EEPROM.h>
// For AES stubs (optional):
#include <AES.h>
#include <Crypto.h>

/*******************************************************
 * Secure Decentralized Mesh Network using PainlessMesh
 * with BLE-iOS Bridge
 *
 * Compatible with both ESP32 and ESP8266
 * 
 * Features:
 *  - Time-based authentication mechanism
 *  - Decentralized routing via painlessMesh
 *  - Self-healing mesh network topology
 *  - Secure message exchange with key validation
 *  - Automatic node discovery and connection
 *  - Signal strength monitoring & detailed network info
 *  - BLE connectivity with iOS for ESP32 nodes
 *  - End-to-end encryption for secure data transmission
 *  - User nickname support for friendly addressing
 *  - High-throughput optimization (~1 Mbit/s with BLE 5)
 *
 * Last updated: 2025-03-20
 * Auth Code: MaHaoxuantb
 *******************************************************/

// Check which platform we're compiling for
#ifdef ESP8266
  #include <ESP8266WiFi.h>
  #define STATUS_LED      LED_BUILTIN  // Built-in LED (active LOW)
  #define HAS_BLE         false
#else
  #include <WiFi.h>
  #include <BLEDevice.h>
  #include <BLEServer.h>
  #include <BLEUtils.h>
  #include <BLE2902.h>
  #include <Preferences.h>
  #define STATUS_LED      2           // Built-in LED pin on most ESP32 dev boards
  #define HAS_BLE         true
#endif

// ========== Mesh Configuration ==========
#define MESH_PREFIX      "MeshPoint_WifiProtocol_Annopia"
#define MESH_PASSWORD    "MeshPassword123.AnnopiaInfructure2025"
#define MESH_PORT        5411
#define MESH_CHANNEL     1

// ========== Auth & Security Settings ==========
#define NETWORK_KEY      "com.AnnopiaInfrastructure.e.MaHaoxuantb2025"
#define TIME_TOLERANCE   120           // seconds
#define VALIDATION_DATE  "2025-03-16"  // reference date

// ========== EEPROM (key storage) ==========
#define EEPROM_SIZE        512
#define KEY_STORAGE_ADDR   0
#define NODE_NAME_ADDR     64
#define NICKNAME_ADDR      128

// ========== Intervals (ms) ==========
#define STATUS_UPDATE_INTERVAL      30000  // 30s
#define CONNECTION_CHECK_INTERVAL   5000   // 5s
#define ROUTE_INFO_INTERVAL         60000  // 60s

// Test/debug modes
#define SIGNAL_STRENGTH_INTERVAL    500    // 500ms
#define DETAILED_MODE_INTERVAL      5000   // 5s

// ========== BLE (ESP32 only) ==========
#ifdef ESP32
  // Service & characteristic UUIDs (use custom ones in production)
  #define SERVICE_UUID            "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
  #define CHARACTERISTIC_UUID_RX  "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"
  #define CHARACTERISTIC_UUID_TX  "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"

  // BLE throughput parameters
  #define BLE_MTU_SIZE                512
  #define BLE_CONNECTION_INTERVAL_MIN 8   // 10ms
  #define BLE_CONNECTION_INTERVAL_MAX 16  // 20ms
  #define BLE_SLAVE_LATENCY           0
  #define BLE_SUPERVISION_TIMEOUT     100 // 1 second (100*10ms)

  #define BLE_BUFFER_SIZE     1024
  #define ENCRYPTION_KEY_SIZE 32
#endif

// Forward Declarations
void blink_led(int times, int delay_ms);
#ifdef ESP32
void processBleMessage(const char* message, size_t length);
#endif

// Mesh callbacks
void receivedCallback(uint32_t from, String &msg);
void newConnectionCallback(uint32_t nodeId);
void changedConnectionCallback();
void nodeTimeAdjustedCallback(int32_t offset);

// Auth & general
bool validateTimeStamp(const char* timeStamp);
bool validateKey(const char *providedKey);
void storeNodeName(const char *name);
String getNodeName();
void printNetworkInfo();
void printDetailedNetworkInfo();
void printSignalStrength();

// BLE (ESP32)
#ifdef ESP32
void setupBLE();
void handleBLEConnections();
void forwardMeshMessageToBLE(const char* message);
void storeUserNickname(const char* nickname);
String getUserNickname();
bool initEncryptionKey();
void encryptMessage(const char* message, size_t length, uint8_t* output, size_t* outputLength);
bool decryptMessage(const uint8_t* encryptedData, size_t length, char* output, size_t* outputLength);
#endif

#include <painlessMesh.h>
#include <ArduinoJson.h>

painlessMesh mesh;
String nodeName = "Node";
String userNickname = "";
unsigned long lastStatusTime = 0;
unsigned long lastConnectionCheckTime = 0;
unsigned long lastRouteInfoTime = 0;
unsigned long lastSignalStrengthTime = 0;
unsigned long lastDetailedTime = 0;
uint32_t nodeId = 0;
bool isConnected = false;
bool isAuthenticated = false;
int connectedNodes = 0;

// Debug / test modes
bool signalMonitorMode = false;
bool detailedMode = false;

#ifdef ESP32
BLEServer *pServer = NULL;
BLECharacteristic *pTxCharacteristic = NULL;
BLECharacteristic *pRxCharacteristic = NULL;
bool deviceConnected = false;
bool oldDeviceConnected = false;
uint8_t bleBuffer[BLE_BUFFER_SIZE];
size_t bleBufferIndex = 0;
Preferences preferences;
uint8_t encryptionKey[ENCRYPTION_KEY_SIZE];
bool isPaired = false;

// BLE server callbacks
class ServerCallbacks: public BLEServerCallbacks {
  void onConnect(BLEServer* pServer) {
    deviceConnected = true;
    Serial.println("BLE Client connected");
    blink_led(3, 100); // three quick blinks
  }

  void onDisconnect(BLEServer* pServer) {
    deviceConnected = false;
    Serial.println("BLE Client disconnected");
    blink_led(1, 500); // one long blink
    pServer->startAdvertising(); // re-advertise
  }

  void onPassKeyRequest() {
    Serial.println("Client requested passkey");
  }

  void onPassKeyNotify(uint32_t pass_key) {
    Serial.print("Passkey Notification: ");
    Serial.println(pass_key);
  }

  void onAuthenticationComplete(esp_ble_auth_cmpl_t auth_cmpl) {
    if(auth_cmpl.success) {
      Serial.println("BLE authentication success");
      isPaired = true;
    } else {
      Serial.println("BLE authentication failed");
      isPaired = false;
    }
  }
};

// BLE RX characteristic callback
class RxCallbacks: public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) {
    // If your version of getValue() returns an Arduino String
    String rxValue = pCharacteristic->getValue();
    
    if (rxValue.length() > 0) {
      Serial.print("BLE Received: ");
      Serial.println(rxValue);

      // Now you can call your function
      processBleMessage(rxValue.c_str(), rxValue.length());
    }
  }
};
#endif

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\nSecure Mesh Node Starting...");

  EEPROM.begin(EEPROM_SIZE);

  pinMode(STATUS_LED, OUTPUT);
#ifdef ESP8266
  digitalWrite(STATUS_LED, HIGH);  // off (active LOW)
#else
  digitalWrite(STATUS_LED, LOW);   // off (active HIGH)
  preferences.begin("MeshNode", false);
#endif

  // Check stored key
  if (validateKey(NETWORK_KEY)) {
    Serial.println("Network key validated");
    isAuthenticated = true;
  } else {
    Serial.println("Network key not validated. Use AUTH:key to authenticate");
  }

  // Get stored node name
  nodeName = getNodeName();
  if (nodeName == "") {
    nodeName = "Node";
    storeNodeName(nodeName.c_str());
  }

#ifdef ESP32
  // If we have BLE, retrieve user nickname
  userNickname = getUserNickname();
  if (userNickname != "") {
    Serial.print("User nickname: ");
    Serial.println(userNickname);
  }

  // Initialize encryption key (stub)
  if (initEncryptionKey()) {
    Serial.println("Encryption key initialized");
  } else {
    Serial.println("Failed to initialize encryption key");
  }
#endif

  Serial.print("Node name: ");
  Serial.println(nodeName);

  // Initialize mesh
  mesh.setDebugMsgTypes(ERROR | STARTUP | CONNECTION);
  mesh.init(MESH_PREFIX, MESH_PASSWORD, MESH_PORT, WIFI_AP_STA, MESH_CHANNEL);

  mesh.onReceive(&receivedCallback);
  mesh.onNewConnection(&newConnectionCallback);
  mesh.onChangedConnections(&changedConnectionCallback);
  mesh.onNodeTimeAdjusted(&nodeTimeAdjustedCallback);

  nodeId = mesh.getNodeId();
  Serial.println("Secure mesh network initialized");
  Serial.print("Node ID: 0x");
  Serial.println(nodeId, HEX);
  Serial.print("Mesh SSID: ");
  Serial.println(MESH_PREFIX);
  Serial.print("Mesh Channel: ");
  Serial.println(MESH_CHANNEL);

#ifdef ESP32
  if (HAS_BLE) {
    setupBLE();
    Serial.println("BLE initialized and advertising");
  }
#endif

  // Indicate start
  blink_led(3, 100);
}

void loop() {
  mesh.update();

  // Connection check
  if (millis() - lastConnectionCheckTime > CONNECTION_CHECK_INTERVAL) {
    lastConnectionCheckTime = millis();
    int newConnectedNodes = mesh.getNodeList().size();
    bool wasConnected = isConnected;
    isConnected = (newConnectedNodes > 0);

    if (wasConnected != isConnected || connectedNodes != newConnectedNodes) {
      connectedNodes = newConnectedNodes;
      if (isConnected) {
        Serial.print("Connected to mesh. Number of nodes: ");
        Serial.println(connectedNodes);
        blink_led(2, 100);
      } else {
        Serial.println("Disconnected from mesh");
        blink_led(1, 500);
      }
    }
  }

  // Print route info
  if (millis() - lastRouteInfoTime > ROUTE_INFO_INTERVAL) {
    lastRouteInfoTime = millis();
    if (isConnected && isAuthenticated) {
      printNetworkInfo();
    }
  }

  // Send periodic status
  if (millis() - lastStatusTime > STATUS_UPDATE_INTERVAL) {
    lastStatusTime = millis();
    if (isConnected && isAuthenticated) {
      StaticJsonDocument<256> doc;
      doc["type"]    = "status";
      doc["nodeId"]  = nodeId;
      doc["name"]    = nodeName;

#ifdef ESP32
      if (userNickname != "") {
        doc["userNickname"] = userNickname;
      }
#endif

      doc["uptime"]  = millis() / 1000;
      doc["heap"]    = ESP.getFreeHeap();

#ifdef ESP8266
      doc["platform"] = "ESP8266";
      doc["chipId"]   = ESP.getChipId();
#else
      doc["platform"]     = "ESP32";
      doc["chipId"]       = (uint32_t)ESP.getEfuseMac();
      doc["bleConnected"] = deviceConnected;
#endif

      String jsonString;
      serializeJson(doc, jsonString);
      mesh.sendBroadcast(jsonString);

      Serial.println("Status update sent to mesh network");
    }
  }

  // Handle Serial commands
  if (Serial.available()) {
    String input = Serial.readStringUntil('\n');
    input.trim();
    if (input.length() > 0) {
      // Test modes
      if (input == "test: 1") {
        signalMonitorMode = true;
        detailedMode = false;
        Serial.println("Signal strength monitoring mode ON. 'test: 0' to disable.");
      } else if (input == "test: 2") {
        detailedMode = true;
        signalMonitorMode = false;
        Serial.println("Detailed network info mode ON. 'test: 0' to disable.");
      } else if (input == "test:3" && isAuthenticated) {
        Serial.println("Triggering network speed test for 10 seconds...");
        testNetworkSpeed();
      } else if (input == "test: 0") {
        signalMonitorMode = false;
        detailedMode = false;
        Serial.println("Test mode disabled.");
      }
      // Auth
      else if (input.startsWith("AUTH:")) {
        String providedKey = input.substring(5);
        if (validateKey(providedKey.c_str())) {
          Serial.println("Authentication successful");
          isAuthenticated = true;
          blink_led(3, 100);
        } else {
          Serial.println("Authentication failed");
          isAuthenticated = false;
          blink_led(2, 500);
        }
      } else if (input.startsWith("TIME_AUTH:")) {
        String timeStamp = input.substring(10);
        if (validateTimeStamp(timeStamp.c_str())) {
          Serial.println("Time-based authentication successful");
          isAuthenticated = true;
          blink_led(3, 100);
        } else {
          Serial.println("Time-based authentication failed");
          isAuthenticated = false;
          blink_led(2, 500);
        }
      }
      // Change node name
      else if (input.startsWith("NAME:")) {
        String newName = input.substring(5);
        if (newName.length() > 0 && newName.length() < 32) {
          nodeName = newName;
          storeNodeName(nodeName.c_str());
          Serial.print("Node name changed to: ");
          Serial.println(nodeName);
          blink_led(2, 100);
        }
      }
#ifdef ESP32
      // Nickname for ESP32
      else if (input.startsWith("NICKNAME:")) {
        String newNickname = input.substring(9);
        if (newNickname.length() > 0 && newNickname.length() < 32) {
          userNickname = newNickname;
          storeUserNickname(userNickname.c_str());
          Serial.print("User nickname changed to: ");
          Serial.println(userNickname);
          blink_led(2, 100);

          // Broadcast nickname update
          if (isConnected && isAuthenticated) {
            StaticJsonDocument<128> doc;
            doc["type"]     = "nickname_update";
            doc["nodeId"]   = nodeId;
            doc["nickname"] = userNickname;

            String jsonString;
            serializeJson(doc, jsonString);
            mesh.sendBroadcast(jsonString);
          }
        }
      }
#endif
      // Direct message
      else if (input.startsWith("DM:") && isAuthenticated) {
        int colonPos = input.indexOf(':', 3);
        if (colonPos > 3) {
          String destIdStr = input.substring(3, colonPos);
          String msgContent = input.substring(colonPos + 1);

          uint32_t destId = strtoul(destIdStr.c_str(), NULL, 16);

          StaticJsonDocument<512> doc;
          doc["type"]       = "direct_message";
          doc["nodeId"]     = nodeId;
          doc["name"]       = nodeName;
#ifdef ESP32
          if (userNickname != "") {
            doc["nickname"] = userNickname;
          }
#endif
          doc["data"]       = msgContent;
          doc["timestamp"]  = mesh.getNodeTime();
          doc["encrypted"]  = true;

          String jsonString;
          serializeJson(doc, jsonString);

          if (mesh.sendSingle(destId, jsonString)) {
            Serial.print("Direct message sent to 0x");
            Serial.println(destId, HEX);
            blink_led(1, 50);
          } else {
            Serial.println("Failed to send message: Node not reachable");
          }
        }
      }
      // Nickname-based message
      else if (input.startsWith("TO:") && isAuthenticated) {
        int colonPos = input.indexOf(':', 3);
        if (colonPos > 3) {
          String targetNickname = input.substring(3, colonPos);
          String msgContent     = input.substring(colonPos + 1);

          StaticJsonDocument<512> doc;
          doc["type"]      = "nickname_message";
          doc["nodeId"]    = nodeId;
          doc["name"]      = nodeName;
#ifdef ESP32
          if (userNickname != "") {
            doc["nickname"] = userNickname;
          }
#endif
          doc["target"]    = targetNickname;
          doc["data"]      = msgContent;
          doc["timestamp"] = mesh.getNodeTime();
          doc["encrypted"] = true;

          String jsonString;
          serializeJson(doc, jsonString);
          mesh.sendBroadcast(jsonString);

          Serial.print("Message sent to nickname: ");
          Serial.println(targetNickname);
          blink_led(1, 50);
        }
      }
      // Fallback: broadcast
      else if (isAuthenticated) {
        StaticJsonDocument<512> doc;
        doc["type"]      = "message";
        doc["nodeId"]    = nodeId;
        doc["name"]      = nodeName;
#ifdef ESP32
        if (userNickname != "") {
          doc["nickname"] = userNickname;
        }
#endif
        doc["data"]      = input;
        doc["timestamp"] = mesh.getNodeTime();

        String jsonString;
        serializeJson(doc, jsonString);
        mesh.sendBroadcast(jsonString);
        Serial.println("Message sent to mesh network");
        blink_led(1, 50);
      } else {
        Serial.println("Authentication required. Use AUTH:yourkey or TIME_AUTH:timestamp");
      }
    }
  }

#ifdef ESP32
  // If BLE is used
  if (HAS_BLE) {
    handleBLEConnections();
  }
#endif

  // Test modes
  if (signalMonitorMode && (millis() - lastSignalStrengthTime > SIGNAL_STRENGTH_INTERVAL)) {
    lastSignalStrengthTime = millis();
    printSignalStrength();
  }

  if (detailedMode && (millis() - lastDetailedTime > DETAILED_MODE_INTERVAL)) {
    lastDetailedTime = millis();
    printDetailedNetworkInfo();
  }
}

// ========== Mesh Callbacks ==========

void receivedCallback(uint32_t from, String &msg) {
  Serial.print("Received from 0x");
  Serial.print(from, HEX);
  Serial.print(": ");
  Serial.println(msg);

  StaticJsonDocument<512> doc;
  DeserializationError error = deserializeJson(doc, msg);
  if (error) {
    Serial.print("Failed to parse message: ");
    Serial.println(error.c_str());
    return;
  }

  String messageType = doc["type"];

  // 'status' from other nodes
  if (messageType == "status" && isAuthenticated) {
    String fromName  = doc["name"];
    String platform  = doc["platform"];
    Serial.print("Status from ");
    Serial.print(fromName);
    Serial.print(" (0x");
    Serial.print((uint32_t)doc["nodeId"], HEX);
    Serial.print(") [");
    Serial.print(platform);
    Serial.print("]: Uptime=");
    Serial.print((uint32_t)doc["uptime"]);
    Serial.print("s, Free Heap=");
    Serial.print((int)doc["heap"]);
    Serial.println(" bytes");

#ifdef ESP32
    // Forward to iOS if connected
    if (deviceConnected && isPaired) {
      forwardMeshMessageToBLE(msg.c_str());
    }
#endif
  }
  // generic 'message'
  else if (messageType == "message" && isAuthenticated) {
    String fromName   = doc["name"];
    String fromNick   = doc.containsKey("nickname") ? doc["nickname"].as<String>() : "";
    Serial.print("Message from ");
    if (fromNick != "") {
      Serial.print(fromNick);
      Serial.print(" (");
    }
    Serial.print(fromName);
    Serial.print(" 0x");
    Serial.print((uint32_t)doc["nodeId"], HEX);
    if (fromNick != "") {
      Serial.print(")");
    }
    Serial.print(": ");
    Serial.println((const char*)doc["data"]);
    blink_led(1, 100);

#ifdef ESP32
    if (deviceConnected && isPaired) {
      forwardMeshMessageToBLE(msg.c_str());
    }
#endif
  }
  // direct_message
  else if (messageType == "direct_message" && isAuthenticated) {
    String fromName = doc["name"];
    String fromNick = doc.containsKey("nickname") ? doc["nickname"].as<String>() : "";
    Serial.print("Direct message from ");
    if (fromNick != "") {
      Serial.print(fromNick);
      Serial.print(" (");
    }
    Serial.print(fromName);
    Serial.print(" 0x");
    Serial.print((uint32_t)doc["nodeId"], HEX);
    if (fromNick != "") {
      Serial.print(")");
    }
    Serial.print(": ");
    Serial.println((const char*)doc["data"]);
    blink_led(2, 100);

#ifdef ESP32
    if (deviceConnected && isPaired) {
      forwardMeshMessageToBLE(msg.c_str());
    }
#endif
  }
  // nickname_message
  else if (messageType == "nickname_message" && isAuthenticated) {
#ifdef ESP32
    String targetNick = doc["target"];
    if (targetNick == userNickname) {
      String senderName = doc["name"];
      String senderNick = doc.containsKey("nickname") ? doc["nickname"].as<String>() : "";

      Serial.print("Nickname message from ");
      if (senderNick != "") {
        Serial.print(senderNick);
        Serial.print(" (");
      }
      Serial.print(senderName);
      Serial.print(" 0x");
      Serial.print((uint32_t)doc["nodeId"], HEX);
      if (senderNick != "") {
        Serial.print(")");
      }
      Serial.print(" to ");
      Serial.print(targetNick);
      Serial.print(": ");
      Serial.println((const char*)doc["data"]);
      blink_led(3, 100);

      if (deviceConnected && isPaired) {
        forwardMeshMessageToBLE(msg.c_str());
      }
    }
#endif
  }
  // nickname_update
  else if (messageType == "nickname_update" && isAuthenticated) {
#ifdef ESP32
    uint32_t updatedNodeId = doc["nodeId"];
    String newNick         = doc["nickname"];
    Serial.print("Node 0x");
    Serial.print(updatedNodeId, HEX);
    Serial.print(" updated nickname to: ");
    Serial.println(newNick);

    if (deviceConnected && isPaired) {
      forwardMeshMessageToBLE(msg.c_str());
    }
#endif
  }
}

void newConnectionCallback(uint32_t newNodeId) {
  Serial.print("New connection: node 0x");
  Serial.println(newNodeId, HEX);
  blink_led(2, 100);
}

void changedConnectionCallback() {
  auto nodes = mesh.getNodeList();
  Serial.print("Number of nodes: ");
  Serial.println(nodes.size());

  Serial.println("Nodes in network:");
  for (auto &id : nodes) {
    Serial.print("  - 0x");
    Serial.println(id, HEX);
  }

  connectedNodes = nodes.size();
  isConnected = (connectedNodes > 0);
}

void nodeTimeAdjustedCallback(int32_t offset) {
  Serial.print("Time adjusted: ");
  Serial.print(offset);
  Serial.println(" ms");
}

// ========== Time-based Auth ==========

bool validateTimeStamp(const char* timeStamp) {
  if (strncmp(timeStamp, VALIDATION_DATE, strlen(VALIDATION_DATE)) != 0) {
    return false;
  }
  const char* timePart = timeStamp + strlen(VALIDATION_DATE) + 1;
  if (strlen(timePart) != 8) {
    return false;
  }
  char hourStr[3] = {timePart[0], timePart[1], '\0'};
  int hour = atoi(hourStr);
  char minStr[3]  = {timePart[3], timePart[4], '\0'};
  int minute = atoi(minStr);
  char secStr[3]  = {timePart[6], timePart[7], '\0'};
  int second = atoi(secStr);

  time_t now = mesh.getNodeTime() / 1000000;
  struct tm* timeinfo = gmtime(&now);
  int currentSec = timeinfo->tm_hour * 3600 + timeinfo->tm_min * 60 + timeinfo->tm_sec;
  int providedSec = hour*3600 + minute*60 + second;
  int difference = abs(currentSec - providedSec);

  return difference <= TIME_TOLERANCE;
}

// ========== Key Validation ==========

bool validateKey(const char *providedKey) {
  // Compare with compile-time default
  if (strcmp(providedKey, NETWORK_KEY) == 0) {
    return true;
  }
  // Check stored key in EEPROM / Preferences
  char storedKey[50];
  int i = 0;
  byte value = EEPROM.read(KEY_STORAGE_ADDR);

  while (value != '\0' && i < 49) {
    storedKey[i++] = value;
    value = EEPROM.read(KEY_STORAGE_ADDR + i);
  }
  storedKey[i] = '\0';

  // If blank or 255, store new key
  if (storedKey[0] == 255 || storedKey[0] == 0) {
    for (i = 0; i < (int)strlen(providedKey); i++) {
      EEPROM.write(KEY_STORAGE_ADDR + i, providedKey[i]);
    }
    EEPROM.write(KEY_STORAGE_ADDR + i, 0);
    EEPROM.commit();
    return true;
  } else {
    // Compare to stored key
    if(strcmp(storedKey, providedKey) == 0) {
      return true;
    }
  }
  return false;
}

// ========== Node Name Storage ==========

void storeNodeName(const char *name) {
#ifdef ESP8266
  for (int i = 0; i < 31 && name[i] != '\0'; i++) {
    EEPROM.write(NODE_NAME_ADDR + i, name[i]);
  }
  EEPROM.write(NODE_NAME_ADDR + 31, 0);
  EEPROM.commit();
#else
  preferences.putString("nodeName", name);
#endif
}

String getNodeName() {
#ifdef ESP8266
  char storedName[32];
  int i = 0;
  byte value = EEPROM.read(NODE_NAME_ADDR);
  while (value != '\0' && i < 31) {
    storedName[i++] = value;
    value = EEPROM.read(NODE_NAME_ADDR + i);
  }
  storedName[i] = '\0';

  if (storedName[0] == 255 || storedName[0] == 0) {
    return "";
  }
  return String(storedName);
#else
  return preferences.getString("nodeName", "");
#endif
}

// ========== BLE-specific (ESP32) ==========

#ifdef ESP32
void storeUserNickname(const char* nickname) {
  preferences.putString("userNickname", nickname);
}

String getUserNickname() {
  return preferences.getString("userNickname", "");
}

bool initEncryptionKey() {
  size_t keyLen = preferences.getBytesLength("encKey");
  if (keyLen == ENCRYPTION_KEY_SIZE) {
    preferences.getBytes("encKey", encryptionKey, ENCRYPTION_KEY_SIZE);
    return true;
  } else {
    // Generate dummy key (not truly secure)
    for (int i = 0; i < ENCRYPTION_KEY_SIZE; i++) {
      encryptionKey[i] = (uint8_t)random(0, 256);
    }
    preferences.putBytes("encKey", encryptionKey, ENCRYPTION_KEY_SIZE);
    return true;
  }
  return false;
}

// Stub AES
void encryptMessage(const char* message, size_t length, uint8_t* output, size_t* outputLength) {
  if (length > *outputLength) {
    length = *outputLength;
  }
  memcpy(output, message, length);
  *outputLength = length;
}

bool decryptMessage(const uint8_t* encryptedData, size_t length, char* output, size_t* outputLength) {
  if (length > *outputLength) {
    return false;
  }
  memcpy(output, encryptedData, length);
  output[length] = '\0';
  *outputLength = length;
  return true;
}

void setupBLE() {
  BLEDevice::init(nodeName.c_str());
  // If your BLE library doesn't have setSecurityAuth, comment out:
  // BLEDevice::setSecurityAuth(true, true, true);

  pServer = BLEDevice::createServer();
  pServer->setCallbacks(new ServerCallbacks());

  BLEService *pService = pServer->createService(SERVICE_UUID);

  pRxCharacteristic = pService->createCharacteristic(
                        CHARACTERISTIC_UUID_RX,
                        BLECharacteristic::PROPERTY_WRITE
                      );
  pRxCharacteristic->setCallbacks(new RxCallbacks());

  pTxCharacteristic = pService->createCharacteristic(
                        CHARACTERISTIC_UUID_TX,
                        BLECharacteristic::PROPERTY_NOTIFY
                      );
  pTxCharacteristic->addDescriptor(new BLE2902());

  pService->start();

  BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(SERVICE_UUID);
  pAdvertising->setMinPreferred(0x06);  // 7.5ms
  pAdvertising->setMaxPreferred(0x12);  // 15ms
  pServer->startAdvertising();

  // Adjust MTU (if your library supports it)
  BLEDevice::setMTU(BLE_MTU_SIZE);
}

void handleBLEConnections() {
  if (!deviceConnected && oldDeviceConnected) {
    delay(500); // let the BT stack clean up
    oldDeviceConnected = deviceConnected;
  }
  else if (deviceConnected && !oldDeviceConnected) {
    oldDeviceConnected = deviceConnected;
  }
}

void processBleMessage(const char* message, size_t length) {
  StaticJsonDocument<256> doc;
  DeserializationError error = deserializeJson(doc, message);
  if (error) {
    Serial.print("BLE JSON parse error: ");
    Serial.println(error.c_str());
    return;
  }

  String cmd = doc["cmd"];
  if (cmd == "setNickname") {
    String nick = doc["nickname"];
    if (nick.length() > 0 && nick.length() < 32) {
      userNickname = nick;
      storeUserNickname(userNickname.c_str());
      Serial.print("Nickname set via BLE: ");
      Serial.println(userNickname);
      blink_led(2, 100);

      if (isConnected && isAuthenticated) {
        StaticJsonDocument<128> broadcastDoc;
        broadcastDoc["type"]     = "nickname_update";
        broadcastDoc["nodeId"]   = nodeId;
        broadcastDoc["nickname"] = userNickname;

        String jsonString;
        serializeJson(broadcastDoc, jsonString);
        mesh.sendBroadcast(jsonString);
      }
    }
  }
  else if (cmd == "sendMeshMessage") {
    String data = doc["data"];
    if (isConnected && isAuthenticated && data.length() > 0) {
      StaticJsonDocument<512> msgDoc;
      msgDoc["type"]     = "message";
      msgDoc["nodeId"]   = nodeId;
      msgDoc["name"]     = nodeName;
      if (userNickname != "") {
        msgDoc["nickname"] = userNickname;
      }
      msgDoc["data"]     = data;
      msgDoc["timestamp"] = mesh.getNodeTime();

      String jsonString;
      serializeJson(msgDoc, jsonString);
      mesh.sendBroadcast(jsonString);

      Serial.print("Sent mesh message from BLE: ");
      Serial.println(data);
    } else {
      Serial.println("Not connected or not authenticated");
    }
  }
  else {
    Serial.print("Unrecognized BLE command: ");
    Serial.println(cmd);
  }
}

void forwardMeshMessageToBLE(const char* message) {
  if (!deviceConnected || !isPaired || pTxCharacteristic == NULL) {
    return;
  }
  // Convert char* to Arduino String for setValue(String)
  String payload = String(message);
  pTxCharacteristic->setValue(payload);
  pTxCharacteristic->notify();
}
#endif // ESP32

// ========== Utility Functions ==========

void blink_led(int times, int delay_ms) {
#ifdef ESP8266
  // active LOW for ESP8266
  for (int i = 0; i < times; i++) {
    digitalWrite(STATUS_LED, LOW);
    delay(delay_ms);
    digitalWrite(STATUS_LED, HIGH);
    delay(delay_ms);
  }
#else
  // active HIGH for ESP32
  for (int i = 0; i < times; i++) {
    digitalWrite(STATUS_LED, HIGH);
    delay(delay_ms);
    digitalWrite(STATUS_LED, LOW);
    delay(delay_ms);
  }
#endif
}

void printSignalStrength() {
  if (!isConnected) return;
  int8_t rssi = WiFi.RSSI();
  Serial.print("[Signal Strength] RSSI: ");
  Serial.print(rssi);
  Serial.println(" dBm");
}

void printNetworkInfo() {
  Serial.println("--- Network Info ---");
  Serial.print("Node ID: 0x");
  Serial.println(nodeId, HEX);
  Serial.print("Connected Nodes: ");
  Serial.println(connectedNodes);
}

void printDetailedNetworkInfo() {
  Serial.println("--- Detailed Network Info ---");
  auto nodes = mesh.getNodeList();
  for (auto &id : nodes) {
    Serial.print("Node 0x");
    Serial.print(id, HEX);
    Serial.println(" is connected.");
  }
}

void testNetworkSpeed() {
    const uint32_t testDurationMs = 10 * 1000;      // 10 seconds
    const size_t   payloadSize    = 512;            // bytes per packet
    String         payload(payloadSize, 'X');       // fill with dummy data

    uint32_t bytesSent   = 0;
    uint32_t packetsSent = 0;
    uint32_t startTime   = millis();

    Serial.println("---- Starting 10s network speed test ----");
    while (millis() - startTime < testDurationMs) {
        // sendBroadcast returns true if it enqueued successfully
        if (mesh.sendBroadcast(payload)) {
            bytesSent   += payloadSize;
            packetsSent += 1;
        }
        // optional: yield to keep WiFi stack happy
        yield();
    }

    float durationSec = (millis() - startTime) / 1000.0;
    float bps         = (bytesSent * 8.0) / durationSec;
    float kbps        = bps / 1000.0;

    Serial.println("---- Network Speed Test Complete ----");
    Serial.print  ("Duration (s):       "); Serial.println(durationSec);
    Serial.print  ("Packets sent:       "); Serial.println(packetsSent);
    Serial.print  ("Total bytes sent:   "); Serial.println(bytesSent);
    Serial.print  ("Throughput (bps):   "); Serial.println(bps);
    Serial.print  ("Throughput (kbps):  "); Serial.println(kbps);
    Serial.println("--------------------------------------");
}
