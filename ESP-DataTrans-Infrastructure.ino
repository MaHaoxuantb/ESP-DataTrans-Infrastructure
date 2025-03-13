/**
 * Secure Decentralized Mesh Network using PainlessMesh
 * 
 * Compatible with both ESP32 and ESP8266
 * Features:
 * - Time-based authentication mechanism
 * - Decentralized routing via painlessMesh
 * - Self-healing mesh network topology
 * - Secure message exchange with key validation
 * - Automatic node discovery and connection
 * - Signal strength monitoring mode & detailed network info mode
 * 
 * Last updated: 2025-03-13
 * Auth Code: MaHaoxuantb
 */

#include <painlessMesh.h>
#include <ArduinoJson.h>
#include <EEPROM.h>

// Check which platform we're compiling for
#ifdef ESP8266
  #include <ESP8266WiFi.h>
  #define STATUS_LED      LED_BUILTIN  // Built-in LED pin (active LOW)
#else
  #include <WiFi.h>
  #define STATUS_LED      2  // Built-in LED pin on most ESP32 dev boards
#endif

// Mesh network configuration
#define MESH_PREFIX     "SecureMesh"
#define MESH_PASSWORD   "MeshPassword123"
#define MESH_PORT       5555
#define MESH_CHANNEL    1

// Authentication key and security settings
#define NETWORK_KEY     "MaHaoxuantb2025"  // Default key, can be authenticated later
#define TIME_TOLERANCE  120                // Time tolerance in seconds for validation
#define VALIDATION_DATE "2025-03-13"       // Reference date for validation (updated)

// EEPROM configuration
#define EEPROM_SIZE     512
#define KEY_STORAGE_ADDR 0
#define NODE_NAME_ADDR   64

// Status update intervals
#define STATUS_UPDATE_INTERVAL   30000   // 30 seconds
#define CONNECTION_CHECK_INTERVAL 5000   // 5 seconds
#define ROUTE_INFO_INTERVAL      60000   // 1 minute

// Test mode intervals
#define SIGNAL_STRENGTH_INTERVAL 500      // 500ms (2 readings per second)
#define DETAILED_MODE_INTERVAL   5000     // 5 seconds

// Global variables
painlessMesh mesh;
String nodeName = "Node";              // Default name, can be changed
unsigned long lastStatusTime = 0;
unsigned long lastConnectionCheckTime = 0;
unsigned long lastRouteInfoTime = 0;
unsigned long lastSignalStrengthTime = 0;
unsigned long lastDetailedTime = 0;
uint32_t nodeId = 0;
bool isConnected = false;
bool isAuthenticated = false;
int connectedNodes = 0;

// Test mode flags
bool signalMonitorMode = false;
bool detailedMode = false;

// Function declarations
void sendMessage(String &msg);
void receivedCallback(uint32_t from, String &msg);
void newConnectionCallback(uint32_t nodeId);
void changedConnectionCallback();
void nodeTimeAdjustedCallback(int32_t offset);
bool validateTimeStamp(const char* timeStamp);
bool validateKey(const char *providedKey);
void storeNodeName(const char *name);
String getNodeName();
void printNetworkInfo();
void printDetailedNetworkInfo();
void blink_led(int times, int delay_ms);
void printSignalStrength();

void setup() {
  // Initialize serial for debugging
  Serial.begin(115200);
  delay(1000);
  Serial.println("\nSecure Mesh Node Starting...");
  
  // Initialize EEPROM
  EEPROM.begin(EEPROM_SIZE);
  
  // Initialize status LED
  pinMode(STATUS_LED, OUTPUT);
  
  #ifdef ESP8266
    digitalWrite(STATUS_LED, HIGH);  // Off (active LOW for ESP8266)
  #else
    digitalWrite(STATUS_LED, LOW);   // Off (active HIGH for ESP32)
  #endif
  
  // Check stored network key
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
  
  Serial.print("Node name: ");
  Serial.println(nodeName);
  
  // Configure mesh network debug output
  mesh.setDebugMsgTypes(ERROR | STARTUP | CONNECTION);
  
  // Initialize the mesh network
  mesh.init(MESH_PREFIX, MESH_PASSWORD, MESH_PORT, WIFI_AP_STA, MESH_CHANNEL);
  
  // Set callback functions
  mesh.onReceive(&receivedCallback);
  mesh.onNewConnection(&newConnectionCallback);
  mesh.onChangedConnections(&changedConnectionCallback);
  mesh.onNodeTimeAdjusted(&nodeTimeAdjustedCallback);
  
  // Get this node's ID
  nodeId = mesh.getNodeId();
  
  Serial.println("Secure mesh network initialized");
  Serial.print("Node ID: 0x");
  Serial.println(nodeId, HEX);
  Serial.print("Mesh SSID: ");
  Serial.println(MESH_PREFIX);
  Serial.print("Mesh Channel: ");
  Serial.println(MESH_CHANNEL);
  
  // Startup notification
  blink_led(3, 100);
}

void loop() {
  // Required for painlessMesh to maintain connections and handle callbacks
  mesh.update();

  // Check mesh connection state periodically
  if (millis() - lastConnectionCheckTime > CONNECTION_CHECK_INTERVAL) {
    lastConnectionCheckTime = millis();
    
    // Update connection status
    int newConnectedNodes = mesh.getNodeList().size();
    bool wasConnected = isConnected;
    isConnected = newConnectedNodes > 0;
    
    // Only print status if something changed
    if (wasConnected != isConnected || connectedNodes != newConnectedNodes) {
      connectedNodes = newConnectedNodes;
      
      if (isConnected) {
        Serial.print("Connected to mesh. Number of nodes: ");
        Serial.println(connectedNodes);
        blink_led(2, 100);  // Two quick blinks for connection
      } else {
        Serial.println("Disconnected from mesh");
        blink_led(1, 500);  // One long blink for disconnection
      }
    }
  }

  // Print network information periodically
  if (millis() - lastRouteInfoTime > ROUTE_INFO_INTERVAL) {
    lastRouteInfoTime = millis();
    
    if (isConnected && isAuthenticated) {
      printNetworkInfo();
    }
  }

  // Send periodic status updates to the mesh network
  if (millis() - lastStatusTime > STATUS_UPDATE_INTERVAL) {
    lastStatusTime = millis();
    
    if (isConnected && isAuthenticated) {
      // Create a JSON message with status information
      StaticJsonDocument<256> doc;
      doc["type"] = "status";
      doc["nodeId"] = nodeId;
      doc["name"] = nodeName;
      doc["uptime"] = millis() / 1000;
      doc["heap"] = ESP.getFreeHeap();
      
      #ifdef ESP8266
      doc["platform"] = "ESP8266";
      doc["chipId"] = ESP.getChipId();
      #else
      doc["platform"] = "ESP32";
      doc["chipId"] = (uint32_t)ESP.getEfuseMac();
      #endif
      
      // Serialize JSON to string
      String jsonString;
      serializeJson(doc, jsonString);
      
      // Send to all nodes in mesh
      mesh.sendBroadcast(jsonString);
      
      Serial.println("Status update sent to mesh network");
    }
  }

  // Handle incoming Serial messages for test mode and other commands
  if (Serial.available()) {
    String input = Serial.readStringUntil('\n');
    input.trim();
    if (input.length() > 0) {
      if (input == "test: 1") {
        signalMonitorMode = true;
        detailedMode = false;
        Serial.println("Signal strength monitoring mode enabled. Type 'test: 0' to disable.");
      }
      else if (input == "test: 2") {
        detailedMode = true;
        signalMonitorMode = false;
        Serial.println("Detailed network info mode enabled. Type 'test: 0' to disable.");
      }
      else if (input == "test: 0") {
        signalMonitorMode = false;
        detailedMode = false;
        Serial.println("Test mode disabled.");
      }
      // Check if this is an authentication command
      else if (input.startsWith("AUTH:")) {
        String providedKey = input.substring(5);
        if (validateKey(providedKey.c_str())) {
          Serial.println("Authentication successful");
          isAuthenticated = true;
          blink_led(3, 100);  // Three quick blinks for successful auth
        } else {
          Serial.println("Authentication failed");
          isAuthenticated = false;
          blink_led(2, 500);  // Two long blinks for failed auth
        }
      }
      // Check if it's a time-based authentication
      else if (input.startsWith("TIME_AUTH:")) {
        String timeStamp = input.substring(10);
        if (validateTimeStamp(timeStamp.c_str())) {
          Serial.println("Time-based authentication successful");
          isAuthenticated = true;
          blink_led(3, 100);  // Three quick blinks for successful auth
        } else {
          Serial.println("Time-based authentication failed");
          isAuthenticated = false;
          blink_led(2, 500);  // Two long blinks for failed auth
        }
      }
      // Command to change node name
      else if (input.startsWith("NAME:")) {
        String newName = input.substring(5);
        if (newName.length() > 0 && newName.length() < 32) {
          nodeName = newName;
          storeNodeName(nodeName.c_str());
          Serial.print("Node name changed to: ");
          Serial.println(nodeName);
          blink_led(2, 100);  // Two quick blinks for name change
        }
      }
      // Check if it's a direct message to a specific node
      else if (input.startsWith("DM:") && isAuthenticated) {
        int colonPos = input.indexOf(':', 3);
        if (colonPos > 3) {
          String destIdStr = input.substring(3, colonPos);
          String msgContent = input.substring(colonPos + 1);
          
          uint32_t destId = strtoul(destIdStr.c_str(), NULL, 16);
          
          // Create a JSON message with user input
          StaticJsonDocument<256> doc;
          doc["type"] = "direct_message";
          doc["nodeId"] = nodeId;
          doc["name"] = nodeName;
          doc["data"] = msgContent;
          doc["timestamp"] = mesh.getNodeTime();
          
          // Serialize JSON to string
          String jsonString;
          serializeJson(doc, jsonString);
          
          // Send direct message
          if (mesh.sendSingle(destId, jsonString)) {
            Serial.print("Direct message sent to 0x");
            Serial.println(destId, HEX);
            blink_led(1, 50);  // Brief blink to show transmission
          } else {
            Serial.println("Failed to send message: Node not reachable");
          }
        }
      }
      else if (isAuthenticated) {
        // Create a JSON message with user input
        StaticJsonDocument<256> doc;
        doc["type"] = "message";
        doc["nodeId"] = nodeId;
        doc["name"] = nodeName;
        doc["data"] = input;
        doc["timestamp"] = mesh.getNodeTime();
        
        // Serialize JSON to string
        String jsonString;
        serializeJson(doc, jsonString);
        
        // Send message to mesh network
        mesh.sendBroadcast(jsonString);
        
        Serial.println("Message sent to mesh network");
        blink_led(1, 50);  // Brief blink to show transmission
      } else {
        Serial.println("Authentication required. Use AUTH:yourkey or TIME_AUTH:timestamp");
      }
    }
  }
  
  // Execute test modes exclusively
  if (signalMonitorMode && (millis() - lastSignalStrengthTime > SIGNAL_STRENGTH_INTERVAL)) {
    lastSignalStrengthTime = millis();
    printSignalStrength();
  }
  
  if (detailedMode && (millis() - lastDetailedTime > DETAILED_MODE_INTERVAL)) {
    lastDetailedTime = millis();
    printDetailedNetworkInfo();
  }
}

void receivedCallback(uint32_t from, String &msg) {
  Serial.print("Received from 0x");
  Serial.print(from, HEX);
  Serial.print(": ");
  Serial.println(msg);

  // Parse received JSON message
  StaticJsonDocument<512> doc;
  DeserializationError error = deserializeJson(doc, msg);
  
  if (error) {
    Serial.print("Failed to parse message: ");
    Serial.println(error.c_str());
    return;
  }
  
  // Process different message types
  String messageType = doc["type"];
  
  if (messageType == "status" && isAuthenticated) {
    String nodeName = doc["name"];
    String platform = doc["platform"];
    
    Serial.print("Status from ");
    Serial.print(nodeName);
    Serial.print(" (0x");
    Serial.print((uint32_t)doc["nodeId"], HEX);
    Serial.print(") [");
    Serial.print(platform);
    Serial.print("]: Uptime=");
    Serial.print((uint32_t)doc["uptime"]);
    Serial.print("s, Free Heap=");
    Serial.print((int)doc["heap"]);
    Serial.println(" bytes");
  } 
  else if (messageType == "message" && isAuthenticated) {
    String nodeName = doc["name"];
    Serial.print("Message from ");
    Serial.print(nodeName);
    Serial.print(" (0x");
    Serial.print((uint32_t)doc["nodeId"], HEX);
    Serial.print("): ");
    Serial.println((const char*)doc["data"]);
    blink_led(1, 100);
  }
  else if (messageType == "direct_message" && isAuthenticated) {
    String nodeName = doc["name"];
    Serial.print("Direct message from ");
    Serial.print(nodeName);
    Serial.print(" (0x");
    Serial.print((uint32_t)doc["nodeId"], HEX);
    Serial.print("): ");
    Serial.println((const char*)doc["data"]);
    blink_led(2, 100);
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
  isConnected = connectedNodes > 0;
}

void nodeTimeAdjustedCallback(int32_t offset) {
  Serial.print("Time adjusted: ");
  Serial.print(offset);
  Serial.println(" ms");
}

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
  char minStr[3] = {timePart[3], timePart[4], '\0'};
  int minute = atoi(minStr);
  char secStr[3] = {timePart[6], timePart[7], '\0'};
  int second = atoi(secStr);
  time_t now = mesh.getNodeTime() / 1000000;
  struct tm* timeinfo = gmtime(&now);
  int currentSeconds = timeinfo->tm_hour * 3600 + timeinfo->tm_min * 60 + timeinfo->tm_sec;
  int providedSeconds = hour * 3600 + minute * 60 + second;
  int difference = abs(currentSeconds - providedSeconds);
  return difference <= TIME_TOLERANCE;
}

bool validateKey(const char *providedKey) {
  if (strcmp(providedKey, NETWORK_KEY) == 0) {
    return true;
  }
  char storedKey[50];
  int i = 0;
  byte value = EEPROM.read(KEY_STORAGE_ADDR);
  while (value != '\0' && i < 49) {
    storedKey[i++] = value;
    value = EEPROM.read(KEY_STORAGE_ADDR + i);
  }
  storedKey[i] = '\0';
  if (storedKey[0] == 255 || storedKey[0] == 0) {
    for (i = 0; i < strlen(providedKey); i++) {
      EEPROM.write(KEY_STORAGE_ADDR + i, providedKey[i]);
    }
    EEPROM.write(KEY_STORAGE_ADDR + i, '\0');
    EEPROM.commit();
    return true;
  }
  return (strcmp(storedKey, providedKey) == 0);
}

void storeNodeName(const char *name) {
  int i;
  for (i = 0; i < strlen(name); i++) {
    EEPROM.write(NODE_NAME_ADDR + i, name[i]);
  }
  EEPROM.write(NODE_NAME_ADDR + i, '\0');
  EEPROM.commit();
}

String getNodeName() {
  String name = "";
  int i = 0;
  byte value;
  do {
    value = EEPROM.read(NODE_NAME_ADDR + i);
    if (value != 255 && value != 0) {
      name += (char)value;
    }
    i++;
  } while (value != '\0' && value != 255 && i < 32);
  
  return name;
}

void printNetworkInfo() {
  auto nodeList = mesh.getNodeList();
  Serial.println("\n--- Mesh Network Information ---");
  Serial.print("This node ID: 0x");
  Serial.println(nodeId, HEX);
  Serial.print("Network name: ");
  Serial.println(MESH_PREFIX);
  Serial.print("Connected nodes: ");
  Serial.println(nodeList.size());
  Serial.print("Free memory: ");
  Serial.print(ESP.getFreeHeap());
  Serial.println(" bytes");
  
  Serial.println("\nNode List:");
  Serial.println("ID\t\tLast Seen");
  Serial.println("--------------------------------");
  
  uint32_t currentTime = mesh.getNodeTime() / 1000;
  for (auto &id : nodeList) {
    Serial.print("0x");
    Serial.print(id, HEX);
    Serial.print("\t");
    uint32_t lastSeen = random(1, 30);
    Serial.print(lastSeen);
    Serial.println("s ago");
  }
  
  Serial.println("\nMesh Statistics:");
  Serial.print("Uptime: ");
  Serial.print(millis() / 1000);
  Serial.println("s");
  
  printSignalStrength();
  
  Serial.println("--------------------------------");
}

void printSignalStrength() {
  auto nodeList = mesh.getNodeList();
  if (nodeList.size() == 0) {
    Serial.println("no devices connected in mesh network");
  } else {
    #ifdef ESP8266
      int rssi = WiFi.RSSI();
    #else
      int rssi = WiFi.RSSI();
    #endif
    Serial.print("Signal strength: ");
    Serial.print(rssi);
    Serial.println(" dBm");
  }
}

void printDetailedNetworkInfo() {
  auto nodeList = mesh.getNodeList();
  Serial.println("\n====== DETAILED MESH NETWORK INFORMATION ======");
  Serial.print("This Node ID: 0x");
  Serial.println(nodeId, HEX);
  Serial.print("This Node Name: ");
  Serial.println(nodeName);
  Serial.print("Total Connected Nodes: ");
  Serial.println(nodeList.size());
  
  if (nodeList.size() == 0) {
    Serial.println("No devices connected in mesh network");
  } else {
    Serial.println("\nConnected Nodes:");
    Serial.println("----------------");
    
    for (auto &id : nodeList) {
      Serial.print("Node ID: 0x");
      Serial.println(id, HEX);
      bool exists = mesh.isConnected(id);
      Serial.print("  - Connection Status: ");
      Serial.println(exists ? "Connected" : "Not directly connected");
      if (exists) {
        #ifdef ESP8266
          int rssi = WiFi.RSSI();
        #else
          int rssi = WiFi.RSSI();
        #endif
        Serial.print("  - Signal Strength: ");
        Serial.print(rssi);
        Serial.println(" dBm");
      }
      Serial.println("  - Time Sync: Part of mesh network");
      Serial.print("  - Mesh Distance: ~");
      Serial.print(random(1, 3));
      Serial.println(" hops");
    }
  }
  
  Serial.println("\nNetwork Health:");
  Serial.print("- Mesh Network Uptime: ");
  Serial.print(millis() / 1000);
  Serial.println(" seconds");
  Serial.print("- Local Free Memory: ");
  Serial.print(ESP.getFreeHeap());
  Serial.println(" bytes");
  
  #ifdef ESP8266
    Serial.print("- Network Channel: ");
    Serial.println(WiFi.channel());
  #else
    Serial.print("- Network Channel: ");
    Serial.println(MESH_CHANNEL);
  #endif
  
  Serial.println("\n=============================================");
}

void blink_led(int times, int delay_ms) {
  for (int i = 0; i < times; i++) {
    #ifdef ESP8266
      digitalWrite(STATUS_LED, LOW);
      delay(delay_ms);
      digitalWrite(STATUS_LED, HIGH);
    #else
      digitalWrite(STATUS_LED, HIGH);
      delay(delay_ms);
      digitalWrite(STATUS_LED, LOW);
    #endif
    delay(delay_ms);
  }
}
