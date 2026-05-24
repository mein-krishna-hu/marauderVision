// Change the first line of your app.js to use an explicit map fallback coordinate grid
const map = L.map("map", { trackResize: true }).setView([0, 0], 2);

// 1. Initialize the Leaflet Map with modern dark tiles

const map = L.map("map").setView([0, 0], 2);
L.tileLayer("https://{s}://{z}/{x}/{y}{r}.png", {
  attribution: "&copy; OpenStreetMap contributors &copy; CARTO",
}).addTo(map);

// Layer Group to hold map markers so we can clear them easily on fresh uploads
let markerLayerGroup = L.layerGroup().addTo(map);

// Bind HTML Upload Event Listener
document
  .getElementById("csvFileInput")
  .addEventListener("change", handleWiggleCSV);

function handleWiggleCSV(e) {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function (evt) {
    const fullText = evt.target.result;

    // CRITICAL FIX: Split the file lines and drop the first metadata row
    const lines = fullText.split("\n");
    lines.shift(); // Removes the application hardware metadata string line safely
    const cleanCSVData = lines.join("\n");

    // Parse the cleaned data string via Papa Parse
    Papa.parse(cleanCSVData, {
      header: true,
      skipEmptyLines: true,
      dynamicTyping: true, // Automatically converts coordinates from text to numbers
      complete: function (results) {
        plotWardriveData(results.data);
      },
    });
  };
  reader.readAsText(file);
}

function plotWardriveData(dataRows) {
  // Clear any markers drawn from a previous file upload
  markerLayerGroup.clearLayers();

  let coordinateBounds = [];

  dataRows.forEach((row) => {
    // Fallbacks accommodate field column variations between different firmware updates
    const lat = row.CurrentLatitude || row.lat || row.Latitude;
    const lon = row.CurrentLongitude || row.lon || row.Longitude;
    const ssid = row.SSID || "[Hidden Network]";
    const mac = row.MAC || row.BSSID;
    const rssi = row.RSSI || -100;
    const channel = row.Channel || 1;

    // If coordinates are fully structural numbers, plot them out
    if (typeof lat === "number" && typeof lon === "number") {
      coordinateBounds.push([lat, lon]);

      // Determine marker pin coloring variations dynamically using structural RSSI signal ratings
      let markerColor = "#f87171"; // Weak Signal default color tint (Red)
      if (rssi >= -65)
        markerColor = "#34d399"; // Strong Signal profile (Green)
      else if (rssi < -65 && rssi >= -80) markerColor = "#fbbf24"; // Medium Signal profile (Yellow)

      // Draw a smooth, modern circle vector marker on the display layout canvas
      const marker = L.circleMarker([lat, lon], {
        radius: 6,
        fillColor: markerColor,
        color: "#1e293b", // Dark border ring
        weight: 1,
        fillOpacity: 0.9,
      });

      // Interactive information dialog snippet popup
      marker.bindPopup(`
                <div class="font-mono text-xs text-slate-200">
                    <b class="text-primary text-sm">${ssid}</b><br>
                    <hr class="border-slate-700 my-1">
                    <b>MAC:</b> ${mac}<br>
                    <b>Channel:</b> ${channel}<br>
                    <b>Signal:</b> <span class="font-bold">${rssi} dBm</span>
                </div>
            `);

      markerLayerGroup.addLayer(marker);
    }
  });

  // Zoom and pan the map instantly to frame all uploaded data points perfectly
  if (coordinateBounds.length > 0) {
    map.fitBounds(L.latLngBounds(coordinateBounds), { padding: [30, 30] });
  } else {
    alert(
      "Parsing complete, but no valid GPS coordinates were found in this file.",
    );
  }
}
