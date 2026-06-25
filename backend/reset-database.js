const mongoose = require("mongoose");

const FlowLog = require("./models/FlowLog");
const Alert = require("./models/Alert");

async function resetDatabase() {

  await mongoose.connect("mongodb://127.0.0.1:27017/malware_detection");

  await FlowLog.deleteMany({});
  await Alert.deleteMany({});

  console.log("✅ Database reset complete");

  process.exit();
}

resetDatabase();