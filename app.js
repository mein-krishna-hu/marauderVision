// ============================================================
//  MarauderEx Analyzer — app.js
//  Fully offline, client-side analysis of ESP32 Marauder SD
// ============================================================

// ============================================================
//  STATE
// ============================================================
const state = {
  loadedFiles: [],
  parsed: {
    wardrive:  [],   // WiGLE CSV access-point records
    pcaps:     {},   // { filename: [packet, …] }
    aps:       [],   // APs_N.log JSON
    airtags:   [],   // Airtags_N.log JSON
    ssids:     [],   // SSIDs_N.log JSON
    gps:       {},   // { filename: { track, waypoints } }
    scanLogs:  {},   // { filename: rawText }
  },
  charts: {},
  maps:   {},
};

// ============================================================
//  NAVIGATION
// ============================================================
const PAGE_META = {
  dashboard: ['Dashboard',    'Overview of captured data'],
  wardrive:  ['Wardrive Map', 'WiFi access points mapped with GPS'],
  pcap:      ['PCAP Viewer',  'Captured 802.11 frames'],
  devices:   ['Devices',      'Access points, AirTags & SSIDs'],
  gps:       ['GPS Tracks',   'GPS tracker routes & points of interest'],
  scanlogs:  ['Scan Logs',    'Network scan results'],
};

function navigate(page) {
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
  const btn = document.querySelector(`[data-page="${page}"]`);
  if (btn) btn.classList.add('active');

  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const section = document.getElementById(`page-${page}`);
  if (section) section.classList.add('active');

  const [title, subtitle] = PAGE_META[page] || [page, ''];
  document.getElementById('pageTitle').textContent    = title;
  document.getElementById('pageSubtitle').textContent = subtitle;

  if (page === 'wardrive') setTimeout(initWardriveMap, 120);
  if (page === 'gps')      setTimeout(initGPSMap,      120);
  if (page === 'devices')  renderAPTable();
}

// ============================================================
//  DRAG & DROP
// ============================================================
document.addEventListener('dragover', e => {
  e.preventDefault();
  document.getElementById('dropOverlay').classList.add('active');
});

document.addEventListener('dragleave', e => {
  if (e.clientX === 0 && e.clientY === 0)
    document.getElementById('dropOverlay').classList.remove('active');
});

document.addEventListener('drop', e => {
  e.preventDefault();
  document.getElementById('dropOverlay').classList.remove('active');
  handleFileInput(e.dataTransfer.files);
});

// ============================================================
//  FILE HANDLING
// ============================================================
async function handleFileInput(fileList) {
  const files = Array.from(fileList);
  if (!files.length) return;
  for (const f of files) await processFile(f);
  updateFileStatus();
  updateDashboard();
}

async function processFile(file) {
  const name = file.name;
  const nameLow = name.toLowerCase();
  const type = detectFileType(nameLow);

  state.loadedFiles.push({ name, type, size: file.size });

  try {
    if (type === 'pcap') {
      const buf     = await file.arrayBuffer();
      const packets = parsePcap(buf, name);
      if (packets) {
        state.parsed.pcaps[name] = packets;
        addOptionTo('pcapFileSelect', name, name);
      }

    } else if (type === 'wardrive') {
      const text = await file.text();
      const aps  = parseWigleCSV(text);
      state.parsed.wardrive.push(...aps);
      populateWardriveFilters();

    } else if (type === 'aps') {
      const data = JSON.parse(await file.text());
      state.parsed.aps.push(...(Array.isArray(data) ? data : []));

    } else if (type === 'airtags') {
      const data = JSON.parse(await file.text());
      state.parsed.airtags.push(...(Array.isArray(data) ? data : []));

    } else if (type === 'ssids') {
      const data = JSON.parse(await file.text());
      state.parsed.ssids.push(...(Array.isArray(data) ? data : []));

    } else if (type === 'gpx') {
      const text   = await file.text();
      const parsed = parseGPX(text);
      if (parsed) {
        state.parsed.gps[name] = parsed;
        addOptionTo('gpxSelect', name, name);
      }

    } else if (type === 'scanlog') {
      state.parsed.scanLogs[name] = await file.text();
      addOptionTo('scanLogSelect', name, name);
    }
  } catch (err) {
    console.warn(`Failed processing ${name}:`, err);
  }
}

function detectFileType(n) {
  if (n.endsWith('.pcap'))  return 'pcap';
  if (n.endsWith('.gpx'))   return 'gpx';
  if (n.startsWith('wardrive') || n.startsWith('station_wardrive')) return 'wardrive';
  if (n.startsWith('aps_'))      return 'aps';
  if (n.startsWith('airtags_'))  return 'airtags';
  if (n.startsWith('ssids_'))    return 'ssids';
  if (n.endsWith('.log'))   return 'scanlog';
  return 'unknown';
}

function addOptionTo(selectId, value, label) {
  const sel = document.getElementById(selectId);
  if (!sel) return;
  const opt = document.createElement('option');
  opt.value       = value;
  opt.textContent = label;
  sel.appendChild(opt);
  // Auto-select first real option
  if (sel.options.length === 2) sel.value = value;
}

// ============================================================
//  PARSERS — PCAP (Binary 802.11)
// ============================================================
function parsePcap(buffer, filename) {
  try {
    const view = new DataView(buffer);
    if (buffer.byteLength < 24) return null;

    const magic = view.getUint32(0, true);
    if (magic !== 0xa1b2c3d4) {
      console.warn('Invalid PCAP magic in', filename);
      return null;
    }

    let offset  = 24; // skip global header
    const pkts  = [];
    let   idx   = 0;

    while (offset + 16 <= buffer.byteLength) {
      const ts_sec  = view.getUint32(offset,     true);
      const ts_usec = view.getUint32(offset + 4, true);
      const incl    = view.getUint32(offset + 8, true);
      const orig    = view.getUint32(offset + 12, true);
      offset += 16;

      if (incl === 0 || incl > 65535 || offset + incl > buffer.byteLength) break;

      const frame = new Uint8Array(buffer, offset, incl);
      const info  = parse80211Frame(frame);

      pkts.push({
        idx: ++idx,
        timestamp: ts_sec + ts_usec / 1e6,
        length: orig,
        ...info,
      });

      offset += incl;
    }

    return pkts;
  } catch (e) {
    console.warn('PCAP parse error:', e);
    return null;
  }
}

function parse80211Frame(data) {
  const blank = { type:'Unknown', subtype:'Unknown', srcMac:'', dstMac:'', bssid:'', ssid:'' };
  if (data.length < 4) return blank;

  const fc0      = data[0];
  const frameType= (fc0 >> 2) & 0x3;
  const frameSub = (fc0 >> 4) & 0xF;

  const TYPES = { 0:'Management', 1:'Control', 2:'Data' };
  const MGMT  = {
    0:'Association Request', 1:'Association Response',
    2:'Reassociation Request', 3:'Reassociation Response',
    4:'Probe Request', 5:'Probe Response',
    8:'Beacon', 9:'ATIM', 10:'Disassociation',
    11:'Authentication', 12:'Deauthentication', 13:'Action',
  };

  const typeName = TYPES[frameType] || 'Unknown';
  let   subName  = frameSub.toString();
  if (frameType === 0) subName = MGMT[frameSub] || `Mgmt-${frameSub}`;
  else if (frameType === 2) subName = 'Data';
  else if (frameType === 1) subName = 'Control';

  // MAC address extractor
  const mac = start =>
    data.length >= start + 6
      ? Array.from(data.subarray(start, start + 6))
          .map(b => b.toString(16).padStart(2, '0')).join(':').toUpperCase()
      : '';

  const dstMac = mac(4);
  const srcMac = mac(10);
  const bssid  = mac(16);

  // SSID extraction from Beacon / Probe Response / Probe Request
  let ssid = '';
  if (frameType === 0) {
    // Beacon & Probe Response: 24-byte header + 12 fixed = IEs at 36
    // Probe Request: 24-byte header + 0 fixed = IEs at 24
    const ieStart = (frameSub === 4) ? 24 : 36;
    let   pos     = ieStart;
    while (pos + 2 <= data.length) {
      const id  = data[pos];
      const len = data[pos + 1];
      if (id === 0) { // SSID element
        if (len > 0 && pos + 2 + len <= data.length) {
          ssid = Array.from(data.subarray(pos + 2, pos + 2 + len))
                      .map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '·')
                      .join('');
        }
        break;
      }
      if (len === 0 || pos + 2 + len > data.length || pos > 350) break;
      pos += 2 + len;
    }
  }

  // EAPOL detection inside Data frames
  if (frameType === 2 && data.length > 32) {
    const qos    = frameSub >= 8;  // QoS subtypes
    const hdrLen = qos ? 26 : 24;
    // LLC/SNAP (6 bytes) then ethertype at hdrLen+6
    if (data.length > hdrLen + 8) {
      const hi = data[hdrLen + 6];
      const lo = data[hdrLen + 7];
      if (hi === 0x88 && lo === 0x8E) subName = 'EAPOL';
    }
  }

  return { type: typeName, subtype: subName, srcMac, dstMac, bssid, ssid };
}

// ============================================================
//  PARSERS — WiGLE CSV
// ============================================================
function parseWigleCSV(text) {
  const lines  = text.split('\n');
  const result = [];
  // BUG FIX #3: Default to lines.length (skip everything) so a file with
  // no recognisable header never tries to parse the header row as data.
  let start = lines.length;

  // Locate data start (skip WigleWifi app-info line + MAC,SSID column header)
  for (let i = 0; i < Math.min(lines.length, 5); i++) {
    const l = lines[i].trim();
    if (l.startsWith('WigleWifi')) { start = i + 2; break; }  // skip app line + col header
    if (l.startsWith('MAC,'))      { start = i + 1; break; }  // file has no app line
  }

  for (let i = start; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    const f = parseCSVLine(line);
    if (f.length < 11) continue;

    const lat = parseFloat(f[6]);
    const lon = parseFloat(f[7]);
    if (isNaN(lat) || isNaN(lon) || (lat === 0 && lon === 0)) continue;

    // BUG FIX #5: trim() each field — Windows \r\n leaves \r on the last field
    result.push({
      mac:      f[0].trim(),
      ssid:     f[1].trim(),
      authMode: f[2].trim(),
      firstSeen:f[3].trim(),
      channel:  parseInt(f[4])   || 0,
      rssi:     parseInt(f[5])   || -100,
      lat, lon,
      alt:      parseFloat(f[8]) || 0,
      acc:      parseFloat(f[9]) || 0,
      type:     (f[10] || 'WIFI').trim().toUpperCase(),  // e.g. 'WIFI' | 'GSM' | 'LTE'
    });
  }
  return result;
}

function parseCSVLine(line) {
  const fields = [];
  let cur = '', inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"')               inQ = !inQ;  // toggle quoted-string mode
    else if (ch === ',' && !inQ)  { fields.push(cur); cur = ''; }  // real comma
    else                          cur += ch;
  }
  fields.push(cur);  // push the last field (no trailing comma)
  return fields;
}

// BUG FIX #1: Detect cellular auth-mode strings (HSPA;ph, GPRS;nl, LTE…)
function isCellular(authUpper) {
  return authUpper.includes('HSPA')  || authUpper.includes('GPRS') ||
         authUpper.includes('LTE')   || authUpper.includes('CDMA') ||
         authUpper.includes('WCDMA') || authUpper.includes('UMTS') ||
         authUpper.includes('NR;')   || authUpper.startsWith('GSM');
}

function getSecurityLevel(authMode) {
  const a = (authMode || '').toUpperCase();
  // BUG FIX #1: Classify cellular BEFORE the WPA/WEP checks to avoid false matches
  if (isCellular(a))  return 'cellular';
  if (a.includes('WPA3')) return 'wpa3';
  if (a.includes('WPA2')) return 'wpa2';
  if (a.includes('WPA'))  return 'wpa';
  if (a.includes('WEP'))  return 'wep';
  // BUG FIX #4: Use .includes() not === so '[IBSS][ESS]', '[ESS]' etc. all match
  if (a === '' || a.includes('OPEN') || a.includes('[ESS]') || a.includes('[IBSS]')) return 'open';
  return 'unknown';
}

// ============================================================
//  PARSERS — GPX
// ============================================================
function parseGPX(text) {
  try {
    // FIX: Strip XML namespaces so DOM queries work cleanly
    const cleanText = text.replace(/xmlns(:\w+)?="[^"]*"/g, '');
    const doc = new DOMParser().parseFromString(cleanText, 'application/xml');
    
    const track = [], waypoints = [];
    let routeName = '';

    // --- Track points: <trk><trkseg><trkpt> (ESP32 Marauder tracker output) ---
    doc.querySelectorAll('trkpt').forEach(pt => {
      const lat = parseFloat(pt.getAttribute('lat'));
      const lon = parseFloat(pt.getAttribute('lon'));
      if (!isNaN(lat) && !isNaN(lon))
        track.push({
          lat, lon,
          ele: parseFloat(pt.querySelector('ele')?.textContent) || 0,
          time: pt.querySelector('time')?.textContent || '',
        });
    });

    // --- Route points: <rte><rtept> — treat as track when no trkpt found ---
    if (track.length === 0) {
      routeName = doc.querySelector('rte > name')?.textContent || '';
      doc.querySelectorAll('rtept').forEach(pt => {
        const lat = parseFloat(pt.getAttribute('lat'));
        const lon = parseFloat(pt.getAttribute('lon'));
        if (!isNaN(lat) && !isNaN(lon))
          track.push({
            lat, lon,
            ele: parseFloat(pt.querySelector('ele')?.textContent) || 0,
            time: pt.querySelector('time')?.textContent || '',
            name: pt.querySelector('name')?.textContent || '',
          });
      });
    }

    // --- Waypoints: <wpt> (POIs, intersections, named landmarks) ---
    doc.querySelectorAll('wpt').forEach(wpt => {
      const lat = parseFloat(wpt.getAttribute('lat'));
      const lon = parseFloat(wpt.getAttribute('lon'));
      if (!isNaN(lat) && !isNaN(lon))
        waypoints.push({
          lat, lon,
          name: wpt.querySelector('name')?.textContent || 'POI',
          desc: wpt.querySelector('desc')?.textContent || '',
          sym: wpt.querySelector('sym')?.textContent || '',
          ele: parseFloat(wpt.querySelector('ele')?.textContent) || null,
        });
    });

    return { track, waypoints, routeName };
  } catch (e) {
    console.warn('GPX parse error:', e);
    return null;
  }
}
// ============================================================
//  DASHBOARD
// ============================================================
function updateDashboard() {
  const { wardrive, pcaps, aps, airtags } = state.parsed;
  const hasData = wardrive.length || Object.keys(pcaps).length || aps.length || airtags.length;

  document.getElementById('welcomeBanner').style.display   = hasData ? 'none'  : 'flex';
  document.getElementById('statsGrid').style.display       = hasData ? 'grid'  : 'none';
  document.getElementById('chartsRow').style.display       = hasData ? 'grid'  : 'none';
  document.getElementById('loadedFilesSection').style.display = state.loadedFiles.length ? 'block' : 'none';

  // Stat values
  const totalAPs  = wardrive.length + aps.length;
  const openAPs   = wardrive.filter(ap => getSecurityLevel(ap.authMode) === 'open').length
                  + aps.filter(ap => ap.sec === 0).length;
  const totalPkts = Object.values(pcaps).reduce((s, p) => s + p.length, 0);

  setText('val-aps',     totalAPs.toLocaleString());
  setText('val-open',    openAPs.toLocaleString());
  setText('val-packets', totalPkts.toLocaleString());
  setText('val-airtags', airtags.length.toLocaleString());

  renderSecChart();
  renderFrameChart();
  renderChanChart();
  renderLoadedFiles();
}

function renderSecChart() {
  const counts = { open:0, wep:0, wpa:0, wpa2:0, wpa3:0 };

  state.parsed.wardrive.forEach(ap => {
    const s = getSecurityLevel(ap.authMode);
    if (s in counts) counts[s]++;
    else counts.open++;
  });

  const secMap = { 0:'open',1:'wep',2:'wpa',3:'wpa2',4:'wpa3' };
  state.parsed.aps.forEach(ap => {
    const key = secMap[ap.sec] ?? 'open';
    if (key in counts) counts[key]++;
  });

  if (Object.values(counts).every(v => v === 0)) return;

  destroyChart('sec');
  state.charts.sec = new Chart(getCtx('secChart'), {
    type: 'doughnut',
    data: {
      labels: ['Open','WEP','WPA','WPA2','WPA3'],
      datasets: [{
        data: [counts.open, counts.wep, counts.wpa, counts.wpa2, counts.wpa3],
        backgroundColor: ['#ff4757','#ffa502','#eccc68','#2ed573','#1e90ff'],
        borderColor: '#080810',
        borderWidth: 3,
      }]
    },
    options: chartOptions({ legendPos: 'right' }),
  });
}

function renderFrameChart() {
  const counts = {};
  Object.values(state.parsed.pcaps).flat().forEach(p => {
    counts[p.subtype] = (counts[p.subtype] || 0) + 1;
  });
  if (!Object.keys(counts).length) return;

  const sorted = Object.entries(counts).sort((a,b) => b[1]-a[1]).slice(0, 8);
  const COLORS = {
    'Beacon':'#2ed573','Probe Request':'#00d4ff','Probe Response':'#00b4d8',
    'Deauthentication':'#ff4757','Disassociation':'#ff6b6b',
    'Authentication':'#ffa502','EAPOL':'#ff6b81','Data':'#4a4a6a',
  };

  destroyChart('frame');
  state.charts.frame = new Chart(getCtx('frameChart'), {
    type: 'bar',
    data: {
      labels: sorted.map(([k]) => k),
      datasets: [{
        data: sorted.map(([,v]) => v),
        backgroundColor: sorted.map(([k]) => (COLORS[k] || '#00ff88') + 'aa'),
        borderColor:     sorted.map(([k]) =>  COLORS[k] || '#00ff88'),
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: chartOptions({ noLegend: true, xFontSize: 9 }),
  });
}

function renderChanChart() {
  const counts = {};
  state.parsed.wardrive.forEach(ap => {
    if (ap.channel > 0) counts[ap.channel] = (counts[ap.channel] || 0) + 1;
  });
  if (!Object.keys(counts).length) return;

  const sorted = Object.entries(counts).sort((a,b) => +a[0] - +b[0]);

  destroyChart('chan');
  state.charts.chan = new Chart(getCtx('chanChart'), {
    type: 'bar',
    data: {
      labels: sorted.map(([k]) => `Ch ${k}`),
      datasets: [{
        data: sorted.map(([,v]) => v),
        backgroundColor: 'rgba(0,212,255,0.35)',
        borderColor: '#00d4ff',
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: chartOptions({ noLegend: true, xFontSize: 9 }),
  });
}

function chartOptions({ legendPos = 'bottom', noLegend = false, xFontSize = 10 } = {}) {
  const gridColor = 'rgba(255,255,255,0.05)';
  const tickColor = '#6b6b8a';
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: noLegend
        ? { display: false }
        : { position: legendPos, labels: { color: tickColor, font: { family: 'Outfit', size: 11 }, boxWidth: 11, padding: 8 } },
    },
    scales: noLegend ? {
      x: { ticks:{ color:tickColor, font:{ size: xFontSize } }, grid:{ color:gridColor } },
      y: { ticks:{ color:tickColor }, grid:{ color:gridColor } },
    } : undefined,
  };
}

function renderLoadedFiles() {
  const grid    = document.getElementById('filesGrid');
  const section = document.getElementById('loadedFilesSection');
  if (!state.loadedFiles.length) { section.style.display = 'none'; return; }
  section.style.display = 'block';

  const ICONS = { pcap:'📡',wardrive:'🗺️',aps:'📋',airtags:'🏷️',ssids:'📝',gpx:'🛰️',scanlog:'📊',unknown:'📄' };

  grid.innerHTML = state.loadedFiles.map(f => `
    <div class="file-card">
      <div class="file-card-icon">${ICONS[f.type] || '📄'}</div>
      <div class="file-card-info">
        <div class="file-card-name" title="${esc(f.name)}">${esc(f.name)}</div>
        <div class="file-card-meta">${f.type} · ${fmtBytes(f.size)}</div>
      </div>
    </div>
  `).join('');
}

function updateFileStatus() {
  const n = state.loadedFiles.length;
  document.getElementById('fileStatus').textContent = n ? `${n} file${n!==1?'s':''} loaded` : 'No files loaded';
}

// ============================================================
//  WARDRIVE MAP
// ============================================================
let _wdLayer = null;

function initWardriveMap() {
  if (state.maps.wardrive) { state.maps.wardrive.invalidateSize(); return; }

  const map = L.map('wardriveMap', { center:[20,0], zoom:2 });
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '© OpenStreetMap © CartoDB',
    subdomains: 'abcd',
    maxZoom: 19,
  }).addTo(map);

  state.maps.wardrive = map;
  renderWardriveMarkers();
}

// BUG FIX #2: Added 'cellular' colour (purple) so GSM/LTE towers render distinctly
const SEC_COLORS = {
  open:'#ff4757', wep:'#ffa502', wpa:'#eccc68', wpa2:'#2ed573',
  wpa3:'#1e90ff', cellular:'#bf5fff', unknown:'#555570',
};

function renderWardriveMarkers() {
  const map = state.maps.wardrive;
  if (!map) return;

  if (_wdLayer) _wdLayer.clearLayers();
  else { _wdLayer = L.layerGroup().addTo(map); }

  const filtered = getFilteredWardrive();

  filtered.forEach(ap => {
    const sec      = getSecurityLevel(ap.authMode);
    const color    = SEC_COLORS[sec] || '#8888aa';
    // Cellular towers get a smaller diamond-ish marker (smaller radius)
    const radius   = (ap.type === 'WIFI') ? 6 : 4;

    L.circleMarker([ap.lat, ap.lon], {
      radius, fillColor: color, color: color,
      weight: 1, opacity: 0.9, fillOpacity: 0.7,
    })
    .bindPopup(`
      <div class="popup-ssid">${esc(ap.ssid) || '(Hidden Network)'}</div>
      <div class="popup-row"><span class="popup-label">Type</span><span class="popup-value">${ap.type}</span></div>
      <div class="popup-row"><span class="popup-label">BSSID / ID</span><span class="popup-value">${ap.mac}</span></div>
      <div class="popup-row"><span class="popup-label">Auth / Mode</span><span class="popup-value">${ap.authMode || 'Unknown'}</span></div>
      <div class="popup-row"><span class="popup-label">Channel</span><span class="popup-value">${ap.channel || '—'}</span></div>
      <div class="popup-row"><span class="popup-label">RSSI</span><span class="popup-value">${ap.rssi} dBm</span></div>
      <div class="popup-row"><span class="popup-label">First Seen</span><span class="popup-value">${ap.firstSeen || '—'}</span></div>
      <div class="popup-row"><span class="popup-label">GPS</span><span class="popup-value">${ap.lat.toFixed(5)}, ${ap.lon.toFixed(5)}</span></div>
    `)
    .addTo(_wdLayer);
  });

  if (filtered.length > 0) {
    const bounds = L.latLngBounds(filtered.map(ap => [ap.lat, ap.lon]));
    map.fitBounds(bounds, { padding: [30,30] });
  }

  document.getElementById('wardriveStats').textContent =
    `Showing ${filtered.length.toLocaleString()} of ${state.parsed.wardrive.length.toLocaleString()} access points`;
}

function getFilteredWardrive() {
  const secF  = val('secFilter')  || 'all';
  const chanF = val('chanFilter') || 'all';
  const rssiF = parseInt(val('rssiFilter') || '-100');
  const typeF = val('typeFilter') || 'all';   // NEW: WiFi / GSM / LTE / all

  return state.parsed.wardrive.filter(ap => {
    if (typeF !== 'all' && ap.type !== typeF)                      return false;
    if (secF  !== 'all' && getSecurityLevel(ap.authMode) !== secF) return false;
    if (chanF !== 'all' && String(ap.channel) !== chanF)           return false;
    if (ap.rssi < rssiF)                                           return false;
    return true;
  });
}

function applyWardriveFilter() { renderWardriveMarkers(); }

function populateWardriveFilters() {
  const sel      = document.getElementById('chanFilter');
  const existing = new Set(Array.from(sel.options).map(o => o.value));
  const channels = [...new Set(state.parsed.wardrive.map(ap => ap.channel))]
                    .filter(c => c > 0).sort((a,b) => a-b);
  channels.forEach(ch => {
    if (!existing.has(String(ch))) {
      const opt = document.createElement('option');
      opt.value = ch; opt.textContent = `Channel ${ch}`;
      sel.appendChild(opt);
    }
  });
}

// ============================================================
//  PCAP TABLE
// ============================================================
function renderPcapTable() {
  const filename = val('pcapFileSelect');
  const frameF   = val('frameFilter')   || 'all';
  const macQ     = (val('macSearch') || '').toLowerCase();
  const tbody    = document.getElementById('pcapTableBody');
  const statsRow = document.getElementById('pcapStatsRow');

  if (!filename || !state.parsed.pcaps[filename]) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty-row">Select a PCAP file to view frames</td></tr>';
    statsRow.innerHTML = '';
    return;
  }

  const all = state.parsed.pcaps[filename];

  // Build type stats from full file
  const typeCounts = {};
  all.forEach(p => { typeCounts[p.subtype] = (typeCounts[p.subtype] || 0) + 1; });
  const topTypes = Object.entries(typeCounts).sort((a,b) => b[1]-a[1]).slice(0,6);
  statsRow.innerHTML =
    `<span class="stat-chip">Total <b>${all.length.toLocaleString()}</b></span>` +
    topTypes.map(([k,v]) => `<span class="stat-chip">${k} <b>${v.toLocaleString()}</b></span>`).join('');

  // Filter
  let pkts = all;
  if (frameF !== 'all') pkts = pkts.filter(p => p.subtype === frameF || p.type === frameF);
  if (macQ)             pkts = pkts.filter(p =>
    p.srcMac.toLowerCase().includes(macQ) ||
    p.dstMac.toLowerCase().includes(macQ) ||
    p.bssid.toLowerCase().includes(macQ)
  );

  const shown = pkts.slice(0, 500);

  const colorClass = sub => {
    if (sub === 'Beacon')          return 'frame-beacon';
    if (sub.includes('Probe'))     return 'frame-probe';
    if (sub === 'Deauthentication')return 'frame-deauth';
    if (sub === 'Disassociation')  return 'frame-disassoc';
    if (sub === 'Authentication')  return 'frame-auth';
    if (sub === 'EAPOL')           return 'frame-eapol';
    if (sub === 'Data')            return 'frame-data';
    if (sub === 'Control')         return 'frame-control';
    return '';
  };

  if (!shown.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty-row">No frames match current filters</td></tr>';
    return;
  }

  tbody.innerHTML = shown.map(p => `
    <tr>
      <td>${p.idx}</td>
      <td>${p.timestamp.toFixed(4)}</td>
      <td>${p.type}</td>
      <td class="${colorClass(p.subtype)}">${p.subtype}</td>
      <td>${p.srcMac}</td>
      <td>${p.dstMac}</td>
      <td>${p.bssid}</td>
      <td>${esc(p.ssid)}</td>
      <td>${p.length}</td>
    </tr>
  `).join('');

  if (pkts.length > 500) {
    tbody.innerHTML += `
      <tr><td colspan="9" class="empty-row" style="color:#ffa502;font-style:normal;">
        ⚠ Showing 500 of ${pkts.length.toLocaleString()} frames — apply a filter to narrow results
      </td></tr>`;
  }
}

// ============================================================
//  DEVICE TABLES
// ============================================================
function switchDeviceTab(tab, btn) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById(`tab-${tab}`).classList.add('active');
  if (tab === 'aps')     renderAPTable();
  if (tab === 'airtags') renderAirtagTable();
  if (tab === 'ssids')   renderSSIDTable();
}

const SEC_LABEL = { 0:'Open',1:'WEP',2:'WPA',3:'WPA2',4:'WPA3' };
const SEC_KEY   = { 0:'open',1:'wep',2:'wpa',3:'wpa2',4:'wpa3' };

function renderAPTable() {
  const search = (val('apSearch') || '').toLowerCase();
  const secF   = val('apSecFilter') || 'all';
  let   aps    = state.parsed.aps;

  if (search) aps = aps.filter(ap =>
    (ap.essid || '').toLowerCase().includes(search) ||
    (ap.bssid || '').toLowerCase().includes(search) ||
    (ap.man   || '').toLowerCase().includes(search)
  );
  if (secF !== 'all') aps = aps.filter(ap => String(ap.sec) === secF);

  const tbody = document.getElementById('apTableBody');
  if (!aps.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-row">${state.parsed.aps.length ? 'No APs match filter' : 'Load APs_N.log to see access points'}</td></tr>`;
    return;
  }

  tbody.innerHTML = aps.map(ap => {
    const label = SEC_LABEL[ap.sec] ?? 'Unknown';
    const key   = SEC_KEY[ap.sec]   ?? 'unknown';
    return `
      <tr>
        <td>${ap.essid ? esc(ap.essid) : '<span style="color:#3d3d5c;font-style:italic">(Hidden)</span>'}</td>
        <td>${ap.bssid || '—'}</td>
        <td>${ap.channel ?? '—'}</td>
        <td>${ap.rssi ?? '—'} dBm</td>
        <td><span class="sec-badge ${key}">${label}</span></td>
        <td>${ap.wps ? '✅' : '—'}</td>
        <td>${(ap.packets ?? 0).toLocaleString()}</td>
        <td>${esc(ap.man) || 'Unknown'}</td>
      </tr>`;
  }).join('');
}

function renderAirtagTable() {
  const tbody = document.getElementById('airtagTableBody');
  const tags  = state.parsed.airtags;
  if (!tags.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-row">Load Airtags_N.log to see AirTags</td></tr>';
    return;
  }
  tbody.innerHTML = tags.map((at, i) => `
    <tr>
      <td>${i+1}</td>
      <td>${esc(at.mac) || '—'}</td>
      <td>${at.rssi !== undefined ? at.rssi + ' dBm' : '—'}</td>
      <td>${at.payload_size ?? at.payloadSize ?? '—'}</td>
      <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;font-size:0.73rem">${esc(at.payload) || '—'}</td>
    </tr>
  `).join('');
}

function renderSSIDTable() {
  const tbody = document.getElementById('ssidTableBody');
  const ssids = state.parsed.ssids;
  if (!ssids.length) {
    tbody.innerHTML = '<tr><td colspan="2" class="empty-row">Load SSIDs_N.log to see SSID list</td></tr>';
    return;
  }
  tbody.innerHTML = ssids.map((s, i) => {
    const name = typeof s === 'string' ? s : (s.ssid || s.name || JSON.stringify(s));
    return `<tr><td>${i+1}</td><td>${esc(name)}</td></tr>`;
  }).join('');
}

// ============================================================
//  GPS MAP
// ============================================================
let _gpsTrack = null, _gpsWpts = null;

function initGPSMap() {
  if (state.maps.gps) { state.maps.gps.invalidateSize(); return; }

  const map = L.map('gpsMap', { center:[20,0], zoom:2 });
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '© OpenStreetMap © CartoDB',
    subdomains: 'abcd', maxZoom: 19,
  }).addTo(map);

  state.maps.gps = map;
  renderGPSMap();
}

function renderGPSMap() {
  const filename = val('gpxSelect');
  const map      = state.maps.gps;
  if (!map) return;

  if (_gpsTrack) map.removeLayer(_gpsTrack);
  if (_gpsWpts)  map.removeLayer(_gpsWpts);
  _gpsTrack = _gpsWpts = null;

  if (!filename || !state.parsed.gps[filename]) return;

  const { track, waypoints, routeName } = state.parsed.gps[filename];
  const isRoute = routeName && track.length > 0;

  // --- Draw track / route line ---
  if (track.length > 1) {
    const lineColor = isRoute ? '#ffa502' : '#00ff88'; // orange for route, green for track
    _gpsTrack = L.polyline(
      track.map(p => [p.lat, p.lon]),
      { color: lineColor, weight: 3, opacity: 0.85 }
    ).addTo(map);

    // Start marker (cyan)
    L.circleMarker([track[0].lat, track[0].lon], {
      radius:8, fillColor:'#00d4ff', color:'#fff', weight:2, fillOpacity:1,
    }).bindPopup(`<b style="color:#00d4ff">&#9654; ${isRoute ? 'Route Start' : 'Track Start'}</b>`).addTo(map);

    // End marker (red)
    const last = track[track.length - 1];
    L.circleMarker([last.lat, last.lon], {
      radius:8, fillColor:'#ff4757', color:'#fff', weight:2, fillOpacity:1,
    }).bindPopup(`<b style="color:#ff4757">&#9632; ${isRoute ? 'Route End' : 'Track End'}</b>`).addTo(map);

    map.fitBounds(_gpsTrack.getBounds(), { padding:[30,30] });
  }

  // --- Draw waypoints ---
  _gpsWpts = L.layerGroup();
  waypoints.forEach(wpt => {
    // Build a rich popup with name + desc + elevation
    let popupHtml = `<b style="color:var(--primary)">${esc(wpt.name)}</b>`;
    if (wpt.desc && wpt.desc !== wpt.name)
      popupHtml += `<br><span style="color:#8888aa;font-size:0.85em">${esc(wpt.desc)}</span>`;
    if (wpt.sym)
      popupHtml += `<br><span style="color:#6b6b8a;font-size:0.8em">&#128205; ${esc(wpt.sym)}</span>`;
    if (wpt.ele)
      popupHtml += `<br><span style="color:#6b6b8a;font-size:0.8em">&#8679; ${wpt.ele.toFixed(1)} m</span>`;

    L.marker([wpt.lat, wpt.lon])
     .bindPopup(popupHtml)
     .addTo(_gpsWpts);
  });
  _gpsWpts.addTo(map);

  // If no track but have waypoints — fit to waypoints
  if (track.length <= 1 && waypoints.length > 0) {
    const bounds = L.latLngBounds(waypoints.map(w => [w.lat, w.lon]));
    map.fitBounds(bounds, { padding:[30,30] });
  }

  // --- Info bar ---
  const dist = calcTrackDistance(track);
  const label = isRoute ? `Route: <span class="info-val">${esc(routeName)}</span>&nbsp;&nbsp;` : '';
  const trackInfo = track.length > 1
    ? `${isRoute ? 'Route' : 'Track'} points: <span class="info-val">${track.length.toLocaleString()}</span>&nbsp;&nbsp;Distance: <span class="info-val">~${dist.toFixed(2)} km</span>&nbsp;&nbsp;`
    : `<span style="color:#ffa502">No track data</span>&nbsp;&nbsp;`;
  document.getElementById('gpsInfo').innerHTML =
    label + trackInfo + `Waypoints: <span class="info-val">${waypoints.length}</span>`;
}

function calcTrackDistance(track) {
  let d = 0;
  for (let i = 1; i < track.length; i++)
    d += haversine(track[i-1].lat, track[i-1].lon, track[i].lat, track[i].lon);
  return d;
}

function haversine(lat1, lon1, lat2, lon2) {
  const R  = 6371;
  const dL = (lat2-lat1)*Math.PI/180;
  const dG = (lon2-lon1)*Math.PI/180;
  const a  = Math.sin(dL/2)**2 +
              Math.cos(lat1*Math.PI/180)*Math.cos(lat2*Math.PI/180)*Math.sin(dG/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

// ============================================================
//  SCAN LOG VIEWER
// ============================================================
function renderScanLog() {
  const filename = val('scanLogSelect');
  const viewer   = document.getElementById('logViewer');
  if (!filename || !state.parsed.scanLogs[filename]) {
    viewer.innerHTML = '<span class="empty-row-inline">Select a scan log file to view its contents</span>';
    return;
  }
  viewer.textContent = state.parsed.scanLogs[filename];
}

// ============================================================
//  UTILITIES
// ============================================================
function esc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function val(id) {
  return document.getElementById(id)?.value ?? '';
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function fmtBytes(b) {
  if (b < 1024)       return `${b} B`;
  if (b < 1048576)    return `${(b/1024).toFixed(1)} KB`;
  return `${(b/1048576).toFixed(1)} MB`;
}

function getCtx(id) {
  return document.getElementById(id).getContext('2d');
}

function destroyChart(key) {
  if (state.charts[key]) { state.charts[key].destroy(); delete state.charts[key]; }
}

// ============================================================
//  INIT
// ============================================================
navigate('dashboard');
