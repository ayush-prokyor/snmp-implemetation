const express = require("express");
const http = require("http");
const snmp = require("net-snmp");
const socketIo = require("socket.io");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const port = 3000;

app.use(express.json());
app.use(express.static("public"));

// SNMP Agent Configuration
const agentConfig = {
  host: "127.0.0.1", // Replace with your SNMP agent IP
  port: 161, // Standard SNMP port
  community: "public", // Default community string
};

// Polling configuration
let pollingConfig = {
  isEnabled: false,
  interval: 5000, // Default polling interval in ms (5 seconds)
  type: "get", // Default polling type: 'get' or 'getbulk'
  oids: ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"], // Default OIDs for GET
  oid: "1.3.6.1.2.1.1", // Default OID for GETBULK
  nonRepeaters: 0,
  maxRepetitions: 10,
};

// Store polling results
let pollingResults = [];
let pollingTimer = null;

// Trap configuration
const trapConfig = {
  port: 16200,
  disableAuthorization: true,
};

// Store received traps
const trapHistory = [];

// Create SNMP session
function createSession() {
  return snmp.createSession(agentConfig.host, agentConfig.community, {
    port: agentConfig.port,
    version: snmp.Version2c,
  });
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// GET endpoint
app.get("/api/snmp/get", (req, res) => {
  const oids = req.query.oids?.split(",") || [
    "1.3.6.1.2.1.1.1.0", // System description
    "1.3.6.1.2.1.1.5.0", // System name
  ];

  const session = createSession();

  session.get(oids, (error, varbinds) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: error.toString() });
    }

    const results = varbinds.map((varbind) => {
      if (snmp.isVarbindError(varbind)) {
        return {
          oid: varbind.oid,
          error: snmp.varbindError(varbind),
        };
      } else {
        return {
          oid: varbind.oid,
          value: varbind.value.toString(),
        };
      }
    });

    res.json({ results });
    session.close();
  });
});

// SET endpoint
app.post("/api/snmp/set", (req, res) => {
  const { oid, type, value } = req.body;

  if (!oid || !type || value === undefined) {
    return res
      .status(400)
      .json({ error: "Missing required parameters: oid, type, value" });
  }

  const session = createSession();
  let snmpType;

  // Map string type to net-snmp type
  switch (type.toLowerCase()) {
    case "integer":
      snmpType = snmp.ObjectType.Integer;
      break;
    case "string":
    case "octetstring":
      snmpType = snmp.ObjectType.OctetString;
      break;
    case "oid":
      snmpType = snmp.ObjectType.OID;
      break;
    case "ipaddress":
      snmpType = snmp.ObjectType.IpAddress;
      break;
    default:
      return res.status(400).json({ error: "Invalid type" });
  }

  const varbinds = [
    {
      oid: oid,
      type: snmpType,
      value: value,
    },
  ];

  session.set(varbinds, (error, varbinds) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: error.toString() });
    }

    const results = varbinds.map((varbind) => {
      if (snmp.isVarbindError(varbind)) {
        return {
          oid: varbind.oid,
          error: snmp.varbindError(varbind),
        };
      } else {
        return {
          oid: varbind.oid,
          value: varbind?.value?.toString(),
        };
      }
    });

    res.json({ results });
    session.close();
  });
});

// GETBULK endpoint
app.get("/api/snmp/getbulk", (req, res) => {
  const oid = req.query.oid || "1.3.6.1.2.1.1"; // System MIB
  const nonRepeaters = parseInt(req.query.nonRepeaters || "0");
  const maxRepetitions = parseInt(req.query.maxRepetitions || "10");

  const session = createSession();

  session.getBulk([oid], nonRepeaters, maxRepetitions, (error, varbinds) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: error.toString() });
    }

    // Debug the response
    console.log("GETBULK Response:", JSON.stringify(varbinds, null, 2));

    // Handle empty varbinds
    if (!varbinds || varbinds.length === 0) {
      return res.json({
        results: [],
        message: "No data returned from SNMP agent",
      });
    }

    const results = [];

    // Fix: The response is an array containing an array of varbinds
    // Use the first element which contains the actual varbinds
    const varbindArray = Array.isArray(varbinds[0]) ? varbinds[0] : varbinds;

    // Process each varbind
    varbindArray.forEach((varbind) => {
      if (snmp.isVarbindError(varbind)) {
        results.push({
          oid: varbind.oid,
          error: snmp.varbindError(varbind),
        });
      } else {
        // Format Buffer values as strings
        let formattedValue = varbind.value;

        if (varbind.value && varbind.value.type === "Buffer") {
          formattedValue = Buffer.from(varbind.value.data).toString();
        } else if (varbind.value !== null && varbind.value !== undefined) {
          formattedValue = varbind.value.toString();
        } else {
          formattedValue = "null";
        }

        results.push({
          oid: varbind.oid,
          type: varbind.type,
          value: formattedValue,
        });
      }
    });

    res.json({ results });
    session.close();
  });
});

// WALK endpoint
app.get("/api/snmp/walk", (req, res) => {
  const oid = req.query.oid || "1.3.6.1.2.1.1"; // System MIB
  const session = createSession();

  const results = [];

  function doneCb(error) {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: error.toString() });
    }

    res.json({ results });
    session.close();
  }

  function feedCb(varbinds) {
    varbinds.forEach((varbind) => {
      if (snmp.isVarbindError(varbind)) {
        results.push({
          oid: varbind.oid,
          error: snmp.varbindError(varbind),
        });
      } else {
        results.push({
          oid: varbind.oid,
          value: varbind.value.toString(),
        });
      }
    });
  }

  session.walk(oid, feedCb, doneCb);
});

// Configuration endpoint
app.post("/api/config", (req, res) => {
  const { host, port, community } = req.body;

  if (host) agentConfig.host = host;
  if (port) agentConfig.port = port;
  if (community) agentConfig.community = community;

  res.json({ success: true, config: agentConfig });
});

// NEW: Polling configuration endpoint
app.post("/api/polling/config", (req, res) => {
  const { isEnabled, interval, type, oids, oid, nonRepeaters, maxRepetitions } =
    req.body;

  if (isEnabled !== undefined) pollingConfig.isEnabled = isEnabled;
  if (interval) pollingConfig.interval = interval;
  if (type) pollingConfig.type = type;
  if (oids) pollingConfig.oids = oids;
  if (oid) pollingConfig.oid = oid;
  if (nonRepeaters !== undefined) pollingConfig.nonRepeaters = nonRepeaters;
  if (maxRepetitions !== undefined)
    pollingConfig.maxRepetitions = maxRepetitions;

  // Start or stop polling based on the new configuration
  if (pollingConfig.isEnabled) {
    startPolling();
  } else {
    stopPolling();
  }

  res.json({ success: true, config: pollingConfig });
});

// NEW: Get polling results endpoint
app.get("/api/polling/results", (req, res) => {
  const limit = parseInt(req.query.limit || "10");
  // Return the most recent polling results
  res.json({
    isPolling: pollingConfig.isEnabled,
    config: pollingConfig,
    results: pollingResults.slice(-limit),
  });
});

// NEW: Perform polling function for GET
function pollGet() {
  const session = createSession();

  session.get(pollingConfig.oids, (error, varbinds) => {
    if (error) {
      console.error("Polling error (GET):", error);
      pollingResults.push({
        timestamp: new Date().toISOString(),
        type: "get",
        error: error.toString(),
      });
    } else {
      const results = varbinds.map((varbind) => {
        if (snmp.isVarbindError(varbind)) {
          return {
            oid: varbind.oid,
            error: snmp.varbindError(varbind),
          };
        } else {
          return {
            oid: varbind.oid,
            value: varbind.value.toString(),
          };
        }
      });

      pollingResults.push({
        timestamp: new Date().toISOString(),
        type: "get",
        results: results,
      });
    }

    session.close();

    // Limit the size of polling results to prevent memory issues
    if (pollingResults.length > 100) {
      pollingResults = pollingResults.slice(-100);
    }
  });
}

// NEW: Perform polling function for GETBULK
function pollGetBulk() {
  const session = createSession();

  session.getBulk(
    [pollingConfig.oid],
    pollingConfig.nonRepeaters,
    pollingConfig.maxRepetitions,
    (error, varbinds) => {
      if (error) {
        console.error("Polling error (GETBULK):", error);
        pollingResults.push({
          timestamp: new Date().toISOString(),
          type: "getbulk",
          error: error.toString(),
        });
      } else {
        // Handle empty varbinds
        if (!varbinds || varbinds.length === 0) {
          pollingResults.push({
            timestamp: new Date().toISOString(),
            type: "getbulk",
            results: [],
            message: "No data returned from SNMP agent",
          });
          return;
        }

        const results = [];

        // Process varbinds
        const varbindArray = Array.isArray(varbinds[0])
          ? varbinds[0]
          : varbinds;

        varbindArray.forEach((varbind) => {
          if (snmp.isVarbindError(varbind)) {
            results.push({
              oid: varbind.oid,
              error: snmp.varbindError(varbind),
            });
          } else {
            let formattedValue = varbind.value;

            if (varbind.value && varbind.value.type === "Buffer") {
              formattedValue = Buffer.from(varbind.value.data).toString();
            } else if (varbind.value !== null && varbind.value !== undefined) {
              formattedValue = varbind.value.toString();
            } else {
              formattedValue = "null";
            }

            results.push({
              oid: varbind.oid,
              type: varbind.type,
              value: formattedValue,
            });
          }
        });

        pollingResults.push({
          timestamp: new Date().toISOString(),
          type: "getbulk",
          results: results,
        });
      }

      session.close();

      // Limit the size of polling results to prevent memory issues
      if (pollingResults.length > 100) {
        pollingResults = pollingResults.slice(-100);
      }
    }
  );
}

// NEW: Start polling function
function startPolling() {
  // Stop any existing polling first
  stopPolling();

  // Start a new polling interval
  pollingTimer = setInterval(() => {
    if (pollingConfig.type === "get") {
      pollGet();
    } else if (pollingConfig.type === "getbulk") {
      pollGetBulk();
    }
  }, pollingConfig.interval);

  console.log(
    `Polling started: ${pollingConfig.type.toUpperCase()} every ${
      pollingConfig.interval
    }ms`
  );
}

// NEW: Stop polling function
function stopPolling() {
  if (pollingTimer) {
    clearInterval(pollingTimer);
    pollingTimer = null;
    console.log("Polling stopped");
  }
}

// ========= TRAP FUNCTIONALITY =========

// Set up SNMP trap receiver
const trapCallback = function (error, trap) {
  if (error) {
    console.error("Trap Error:", error.message);
    return;
  }

  const now = new Date();
  const trapType = snmp.PduType[trap.pdu.type] || "Unknown";

  console.log(
    `${now.toLocaleString()}: ${trapType} received from ${trap.rinfo.address}`
  );

  // Create a structure to store trap info
  const trapInfo = {
    timestamp: now.toISOString(),
    source: trap.rinfo.address,
    sourcePort: trap.rinfo.port,
    version: snmp.Version[trap.version] || trap.version,
    community: trap.community || "N/A",
    pdu: {
      type: trapType,
      enterprise: trap.pdu.enterprise ? trap.pdu.enterprise.join(".") : "N/A",
      varbinds: [],
    },
  };

  // Process variable bindings
  if (trap.pdu.varbinds && Array.isArray(trap.pdu.varbinds)) {
    trap.pdu.varbinds.forEach((varbind) => {
      let displayValue = "undefined";

      if (varbind.value !== undefined) {
        // Direct handling for Buffer values when it's type 4 (OctetString)
        if (Buffer.isBuffer(varbind.value) && varbind.type === 4) {
          // Use toString directly on the Buffer
          displayValue = varbind.value.toString("utf8");
          console.log("Converted buffer to string:", displayValue);
        } else if (
          typeof varbind.value === "object" &&
          varbind.value !== null
        ) {
          try {
            displayValue = JSON.stringify(varbind.value);
          } catch (e) {
            displayValue = "[Complex Object]";
          }
        } else {
          displayValue = varbind.value.toString();
        }
      }

      trapInfo.pdu.varbinds.push({
        oid: varbind.oid,
        type: snmp.ObjectType[varbind.type] || varbind.type,
        value: displayValue,
      });

      console.log(`  ${varbind.oid} -> ${displayValue}`);
    });
  }

  // Store trap and limit history to latest 100 traps
  trapHistory.unshift(trapInfo);
  if (trapHistory.length > 100) {
    trapHistory.pop();
  }

  // Emit to all connected clients
  io.emit("newTrap", trapInfo);
};

// Create the receiver with callback
const receiver = snmp.createReceiver(trapConfig, trapCallback);

// Set up authorizer (even though we have disableAuthorization: true)
const authorizer = receiver.getAuthorizer();
authorizer.addCommunity("public");

// Get traps endpoint
app.get("/api/traps", (req, res) => {
  const limit = parseInt(req.query.limit || trapHistory.length);
  res.json({ traps: trapHistory.slice(0, limit) });
});

// Configure trap receiver
app.post("/api/traps/config", (req, res) => {
  const { port } = req.body;

  // Note: Trap port can't be changed at runtime,
  // this would require server restart to take effect
  if (port) {
    trapConfig.port = port;
    res.json({
      success: true,
      config: trapConfig,
      message:
        "Trap port configuration updated. Server restart required to apply changes.",
    });
  } else {
    res.json({ success: true, config: trapConfig });
  }
});

// Socket.io connection handler
io.on("connection", (socket) => {
  console.log("New client connected");

  // Send trap history to newly connected client
  socket.emit("trapHistory", trapHistory);

  socket.on("disconnect", () => {
    console.log("Client disconnected");
  });
});

server.listen(port, "0.0.0.0", () => {
  console.log(`SNMP App listening at http://localhost:${port}`);
  console.log(`SNMP Trap Receiver listening on port ${trapConfig.port}`);
});
