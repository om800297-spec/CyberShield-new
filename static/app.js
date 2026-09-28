
const configs={
message:["MESSAGE ANALYZER","Suspicious Message Checker","Paste an SMS, email or chat message.","Example: Your account will be blocked. Verify immediately at https://example.com"],
url:["URL SCANNER","Inspect a suspicious URL","Check basic structural phishing indicators.","https://example.com/login"],
email:["EMAIL CHECKER","Check an email address","Check basic email format and demo disposable-domain patterns.","name@example.com"],
phone:["MOBILE NUMBER CHECKER","Check a mobile number","Validate basic number structure.","+91 9876543210"],
bank:["BANK SCAM CHECKER","Analyze a bank-related scam","Paste a KYC, UPI, refund or bank message.","Your KYC will expire. Verify now at https://example.com"],
ip:["IP INTELLIGENCE","Inspect an IP address","Validate IPv4 format; production can add authorized reputation APIs.","8.8.8.8"]
};
let current="message", scans=Number(localStorage.csScans||0);
const $=s=>document.querySelector(s), $$=s=>document.querySelectorAll(s);
$("#scanCount").textContent=scans;

const titles={dashboard:"Security Dashboard",scanners:"Threat Scanners",incidents:"Incident Reports",location:"Sender Metadata",police:"Report to Authorities",awareness:"Awareness Center"};
function showPage(id){$$(".page").forEach(p=>p.classList.toggle("active",p.id===id));$$(".nav").forEach(b=>b.classList.toggle("active",b.dataset.page===id));$("#title").textContent=titles[id]}
$$(".nav").forEach(b=>b.onclick=()=>showPage(b.dataset.page));
$$("[data-open]").forEach(b=>b.onclick=()=>{showPage("scanners");selectType(b.dataset.open)});
$$(".tab").forEach(b=>b.onclick=()=>selectType(b.dataset.type));
function selectType(t){current=t;const c=configs[t]||configs.message;$$(".tab").forEach(b=>b.classList.toggle("active",b.dataset.type===t));$("#scanKicker").textContent=c[0];$("#scanTitle").textContent=c[1];$("#scanHelp").textContent=c[2];$("#scanInput").placeholder=c[3];$("#result").classList.add("hidden")}

$("#scan").onclick=async()=>{
 const value=$("#scanInput").value.trim();if(!value){alert("Enter something to analyze.");return}
 $("#scan").disabled=true;$("#scan").textContent="Analyzing...";
 try{
  const r=await fetch("/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({type:current,value})});
  const d=await r.json();const col=d.risk==="HIGH"?"#ff6078":d.risk==="MEDIUM"?"#f4c45b":"#39dda0";
  $("#result").innerHTML=`<h3>Risk: <span style="color:${col}">${d.risk}</span></h3><ul>${d.reasons.map(x=>`<li>${x}</li>`).join("")}</ul><p class="muted">${d.recommendation}</p><button class="primary" id="saveIncident">Create Incident</button>`;
  $("#result").classList.remove("hidden");scans++;localStorage.csScans=scans;$("#scanCount").textContent=scans;
  $("#saveIncident").onclick=()=>createIncident(current,d.risk,value);
 }catch(e){$("#result").innerHTML="<b>API error.</b><p>Make sure the Flask server is running.</p>";$("#result").classList.remove("hidden")}
 $("#scan").disabled=false;$("#scan").textContent="Analyze";
};
$("#clear").onclick=()=>{$("#scanInput").value="";$("#result").classList.add("hidden")};

async function createIncident(type="Suspicious Activity",risk="Medium",description=""){
 const r=await fetch("/api/incidents",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({type,risk,description})});
 const d=await r.json();showPage("incidents");renderIncidents();return d;
}
async function renderIncidents(){
 const r=await fetch("/api/incidents"),list=await r.json();$("#incidentCount").textContent=list.length;
 $("#incidentList").innerHTML=list.length?list.map(x=>`<div class="incident"><b>${x.id} · ${x.type}</b><span class="muted">Risk: ${x.risk} · ${x.status} · ${x.created}</span><p>${x.description||"No description"}</p></div>`).join(""):"<p class='muted'>No incidents created in this session.</p>";
}
$("#createIncident").onclick=()=>createIncident();
$("#locationBtn").onclick=async()=>{
 const indicator=$("#locationInput").value.trim();if(!indicator){alert("Enter a public IPv4 or IPv6 address.");return}
 $("#locationBtn").disabled=true; $("#locationBtn").textContent="Analyzing...";
 try{
  const r=await fetch("/api/location-intelligence",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({indicator,source:"user-provided authorized metadata"})});
  const d=await r.json();
  if(!r.ok){$("#locationResult").innerHTML=`<b>Lookup failed</b><p>${d.message||"Unable to analyze this IP."}</p>`;}
  else {
   $("#locationResult").innerHTML=`
    <div class="meta-head"><div><b>IP Metadata Intelligence</b><p class="muted">${d.message||""}</p></div><span class="meta-risk ${String(d.risk||"").toLowerCase()}">${d.risk||"INFO"}</span></div>
    <div class="meta-grid">
      <div><small>IP Address</small><b>${d.indicator||"N/A"}</b></div>
      <div><small>Country</small><b>${d.country||"N/A"} ${d.country_code&&d.country_code!=="N/A"?`(${d.country_code})`:""}</b></div>
      <div><small>Region</small><b>${d.region||"N/A"}</b></div>
      <div><small>City</small><b>${d.city||"N/A"}</b></div>
      <div><small>Postal</small><b>${d.postal||"N/A"}</b></div>
      <div><small>Timezone</small><b>${d.timezone||"N/A"}</b></div>
      <div><small>ISP</small><b>${d.isp||"N/A"}</b></div>
      <div><small>Organization</small><b>${d.organization||"N/A"}</b></div>
      <div><small>ASN</small><b>${d.asn||"N/A"}</b></div>
      <div><small>Domain</small><b>${d.domain||"N/A"}</b></div>
      <div><small>VPN</small><b>${d.vpn||"Unknown"}</b></div>
      <div><small>Proxy</small><b>${d.proxy||"Unknown"}</b></div>
      <div><small>Tor</small><b>${d.tor||"Unknown"}</b></div>
    </div>
    <p class="meta-note">Source: ${d.source||"public IP intelligence"}. ${d.source_note||""}</p>`;
  }
  $("#locationResult").classList.remove("hidden");
 }catch(e){$("#locationResult").innerHTML="<b>API error.</b><p>Make sure the Flask server and internet connection are available.</p>";$("#locationResult").classList.remove("hidden")}
 $("#locationBtn").disabled=false; $("#locationBtn").textContent="Analyze Metadata";
};
$("#locationClear").onclick=()=>{$("#locationInput").value="";$("#locationResult").classList.add("hidden")};
let latestReport=null;
$("#reportBtn").onclick=async()=>{
 const evidence=$("#reportEvidence").value.trim();
 const r=await fetch("/api/report",{method:"POST",headers:{"Content-Type":"application/json"},
   body:JSON.stringify({incident_id:"User review required",details:{purpose:"Cybercrime/police reporting package",evidence}})});
 const d=await r.json(); latestReport=d;
 $("#reportResult").innerHTML=`<b>${d.report_id}</b><p>Report package prepared. Review it and use the appropriate official cybercrime/police channel for submission.</p>`;
 $("#reportResult").classList.remove("hidden");
};
$("#pdfBtn").onclick=async()=>{
 if(!latestReport){
   const evidence=$("#reportEvidence").value.trim();
   const r=await fetch("/api/report",{method:"POST",headers:{"Content-Type":"application/json"},
     body:JSON.stringify({incident_id:"User review required",details:{purpose:"Cybercrime/police reporting package",evidence}})});
   latestReport=await r.json();
 }
 const r=await fetch("/api/report/pdf",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(latestReport)});
 if(!r.ok){alert("PDF generation failed. Check the server.");return}
 const blob=await r.blob(); const url=URL.createObjectURL(blob);
 const a=document.createElement("a"); a.href=url; a.download=(latestReport.report_id||"cyber_shield_report")+".pdf";
 document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
};
$("#theme").onclick=()=>document.body.classList.toggle("light");
async function health(){try{const r=await fetch("/api/health");$("#api").textContent=r.ok?"API Online":"API Error";$("#api").style.color=r.ok?"var(--accent)":"var(--red)"}catch{$("#api").textContent="API Offline";$("#api").style.color="var(--red)"}}
health();renderIncidents();selectType("message");
