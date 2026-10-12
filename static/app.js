const f=document.getElementById("file"),n=document.getElementById("filename");
if(f&&n)f.addEventListener("change",()=>{n.textContent=f.files.length?f.files[0].name:"Drop a file here or browse";});
