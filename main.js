async function start(){
  await fetch('/start', {method:'POST'});
  setTimeout(fetchAlerts, 500);
}
async function stop(){
  await fetch('/stop', {method:'POST'});
  setTimeout(fetchAlerts, 500);
}
async function fetchAlerts(){
  const res = await fetch('/alerts');
  const data = await res.json();
  const tbody = document.querySelector('#alerts tbody');
  tbody.innerHTML = '';
  for(const a of data.reverse()){
    const tr = document.createElement('tr');
    const now = new Date().toLocaleString();
    tr.innerHTML = `<td>${now}</td><td>${a.src}:${a.src_port||''}</td><td>${a.dst}:${a.dst_port||''}</td><td>${a.alert}</td><td><pre style="white-space:pre-wrap">${a.payload_preview||''}</pre></td>`;
    tbody.appendChild(tr);
  }
}

