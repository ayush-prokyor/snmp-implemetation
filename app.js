const express = require("express");
const dgram = require("dgram");
const snmp = require("net-snmp");
const app = express();
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

// Store polling port: 16200,results
let pollingResults = [];
let pollingTimer = null;

// Trap configuration
// const trapConfig = {
//   // Standard SNMP trap port
//   isEnabled: true, // Default disabled
//   maxTraps: 100, // Maximum number of traps to store
// };

// Store received traps
// let receivedTraps = [];
// let trapListener = null;

// const trapReceiver = snmp.createReceiver({ port: trapConfig.port });

// Create SNMP session
function createSession() {
  return snmp.createSession(agentConfig.host, agentConfig.community, {
    port: agentConfig.port,
    version: snmp.Version2c,
  });
}

app.get("/", (req, res) => {
  res.send("welcome to snmp-server-page");
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

// Start Trap Listener function
// function startTrapListener() {
//   // Stop any existing trap listener
//   stopTrapListener();

//   try {
//     // Create UDP socket for listening to traps

//     trapListener = dgram.createSocket("udp4");

//     // Handle incoming messages
//     trapListener.on("message", function (msg, rinfo) {
//       console.log(
//         "Received potential SNMP trap from:",
//         rinfo.address,
//         rinfo.port
//       );

//       try {
//         // Decode the SNMP message
//         const message = snmp.Message.fromBuffer(msg);

//         // Determine SNMP version
//         let version = "unknown";
//         if (message.version === snmp.Version1) version = "v1";
//         else if (message.version === snmp.Version2c) version = "v2c";
//         else if (message.version === snmp.Version3) version = "v3";

//         console.log(
//           `Parsed SNMP ${version} message:`,
//           JSON.stringify(message, null, 2)
//         );

//         // Prepare trap data
//         const trapInfo = {
//           timestamp: new Date().toISOString(),
//           version: version,
//           sourceAddress: rinfo.address,
//           sourcePort: rinfo.port,
//           community: message.community || "unknown",
//           pdu: message.pdu ? message.pdu.type : "unknown",
//           varbinds: [],
//         };

//         if (message.pdu && message.pdu.varbinds) {
//           trapInfo.varbinds = message.pdu.varbinds.map((vb) => ({
//             oid: vb.oid,
//             value: vb.value ? vb.value.toString() : "unknown",
//           }));
//         }

//         // Store trap
//         receivedTraps.unshift(trapInfo);
//         if (receivedTraps.length > trapConfig.maxTraps) {
//           receivedTraps = receivedTraps.slice(0, trapConfig.maxTraps);
//         }

//         console.log("Traps received:", receivedTraps);
//       } catch (parseError) {
//         console.error("Error parsing SNMP trap:", parseError);
//         receivedTraps.unshift({
//           timestamp: new Date().toISOString(),
//           sourceAddress: rinfo.address,
//           sourcePort: rinfo.port,
//           error: "Failed to parse: " + parseError.message,
//           rawData: msg.toString("hex"),
//         });

//         if (receivedTraps.length > trapConfig.maxTraps) {
//           receivedTraps = receivedTraps.slice(0, trapConfig.maxTraps);
//         }
//       }
//     });

//     trapListener.on("error", function (error) {
//       console.error("Trap listener error:", error);
//     });

//     trapListener.bind(trapConfig.port, function () {
//       console.log(`SNMP Trap listener started on port ${trapConfig.port}`);
//     });
//   } catch (error) {
//     console.error("Failed to start trap listener:", error);
//   }
// }

// Stop Trap Listener function
// function stopTrapListener() {
//   if (trapListener) {
//     try {
//       trapListener.close();
//       trapListener = null;
//       console.log("SNMP Trap listener stopped");
//     } catch (error) {
//       console.error("Error stopping trap listener:", error);
//     }
//   }
// }

// Trap configuration endpoint
// app.post("/api/trap/config", (req, res) => {
//   const { isEnabled, port, maxTraps } = req.body;

//   // Save the current state to check if we need to restart
//   const wasEnabled = trapConfig.isEnabled;
//   const oldPort = trapConfig.port;

//   // Update configuration
//   if (isEnabled !== undefined) trapConfig.isEnabled = isEnabled;
//   if (port) trapConfig.port = parseInt(port);
//   if (maxTraps) trapConfig.maxTraps = parseInt(maxTraps);

//   // Start, stop, or restart trap listener based on configuration changes
//   if (trapConfig.isEnabled) {
//     // If it was already enabled and the port changed, we need to restart
//     if (wasEnabled && oldPort !== trapConfig.port) {
//       stopTrapListener();
//       startTrapListener();
//     }
//     // If it wasn't enabled before, start it
//     else if (!wasEnabled) {
//       startTrapListener();
//     }
//   } else if (wasEnabled) {
//     // If it was enabled and now should be disabled
//     stopTrapListener();
//   }

//   res.json({ success: true, config: trapConfig });
// });

// Get trap results endpoint
// app.get("/api/trap/results", (req, res) => {
//   const limit = parseInt(req.query.limit || "10");
//   // Return the most recent trap results
//   res.json({
//     isListening: trapConfig.isEnabled,
//     config: trapConfig,
//     results: receivedTraps.slice(0, limit),
//   });
// });

// Start trap listener if enabled at startup
// if (trapConfig.isEnabled) {
//   startTrapListener();
// }

app.listen(port, () => {
  console.log(`SNMP Demo app listening at http://localhost:${port}`);
});
