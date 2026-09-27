
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
 const indicator=$("#locationInput").value.trim();if(!indicator){alert("Enter authorized sender metadata.");return}
 const r=await fetch("/api/location-intelligence",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({indicator,source:"user-provided authorized metadata"})});
 const d=await r.json();$("#locationResult").innerHTML=`<b>Metadata-only intelligence</b><p>${d.message}</p><p class="muted">Available production fields: ${d.fields.join(", ")}.</p>`;$("#locationResult").classList.remove("hidden");
};
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
