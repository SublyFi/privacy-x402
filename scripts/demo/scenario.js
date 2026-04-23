const DEMO_ROUTE_PATH = "/weather";
const DEMO_HTTP_METHOD = "GET";
const DEMO_DESCRIPTION = "Weather data";
const DEMO_MIME_TYPE = "application/json";

function buildDemoRequest() {
  return null;
}

function buildDemoResponse({ providerId, settlementMode }) {
  return {
    report: {
      weather: "sunny",
      temperature: 70,
    },
    providerId,
    settlementMode,
  };
}

function requestSummary() {
  return 'AI agent requests paid weather data from "GET /weather"';
}

module.exports = {
  DEMO_DESCRIPTION,
  DEMO_HTTP_METHOD,
  DEMO_MIME_TYPE,
  DEMO_ROUTE_PATH,
  buildDemoRequest,
  buildDemoResponse,
  requestSummary,
};
