const {test}=require('node:test');const assert=require('node:assert/strict');const vm=require('node:vm');const fs=require('node:fs');const path=require('node:path');
function setup(){
 const html=fs.readFileSync(path.join(__dirname,'../static/index.html'),'utf8');const nodes=new Map([...html.matchAll(/id="([^"]+)"/g)].map(m=>[m[1],{id:m[1],value:'',checked:false,disabled:false,textContent:'',children:[],replaceChildren(){this.children=[]},append(n){this.children.push(n)},addEventListener(){},reset(){}}]));
 nodes.get('settings-form').querySelectorAll=()=>[...nodes.values()].filter(n=>/^(smtp|directory|threatfox)-/.test(n.id));const requests=[];
 const view={configured:true,version:1,smtp:{host:'mail.example',port:465,security:'tls',to:[]},directory:{enabled:true,url:'ldaps://dc.example',base_dn:'DC=example',bind_dn:'svc@example',ca_pem:'saved-ca'},directory_password_set:true,history:[]};
 const ctx=vm.createContext({$:(id)=>{assert.ok(nodes.has(id),id);return nodes.get(id)},state:{role:'administrator',csrf:'csrf',view:'settings'},date:String,document:{createElement:()=>({})},api:async(url,options)=>{requests.push({url,body:options?.body&&JSON.parse(options.body)});return url==='api/settings'?{...view,version:2}:{ok:true,message:'verified',account:{state:'verified',sid:'S-1-5-21-1-2-3-1001'}}}});vm.runInContext(fs.readFileSync(path.join(__dirname,'../static/settings.js'),'utf8'),ctx);ctx.renderSettings(view);return {ctx,nodes,requests,view};
}
test('AD settings save independently, redact saved secrets and preserve unsaved SMTP edits',async()=>{
 const {ctx,nodes,requests}=setup();nodes.get('smtp-password').value='unsaved-mail-secret';nodes.get('smtp-console-url').value='https://edited.example/admin/';nodes.get('directory-password').value='new-directory-secret';await ctx.settingsAction('save-directory');
 const req=requests.find(r=>r.url==='api/settings');assert.equal(req.body.scope,'directory');assert.equal(req.body.directory_password,'new-directory-secret');assert.equal(req.body.smtp,undefined);assert.equal(nodes.get('directory-password').value,'');assert.equal(nodes.get('smtp-password').value,'unsaved-mail-secret');assert.equal(nodes.get('smtp-console-url').value,'https://edited.example/admin/');assert.equal(nodes.get('settings-save-directory').disabled,false);
});
test('SMTP save preserves pending AD certificate edit; account check does not save settings',async()=>{
 const {ctx,nodes,requests}=setup();nodes.get('directory-ca-pem').value='edited-ca';await ctx.settingsAction('save-smtp');assert.equal(nodes.get('directory-ca-pem').value,'edited-ca');nodes.get('directory-check-name').value='alice@lab.example';nodes.get('directory-check-realm').value='LAB';nodes.get('directory-check-implicit').checked=true;await ctx.settingsAction('check-directory-account');
 const req=requests.find(r=>r.url.endsWith('check-directory-account'));assert.equal(req.body.name,'alice@lab.example');assert.equal(req.body.implicit_upn,true);assert.equal(requests.filter(r=>r.url==='api/settings').length,1);assert.match(nodes.get('directory-account-result').textContent,/S-1-5-21/);ctx.resetSettings();assert.equal(nodes.get('directory-account-result').textContent,'');
});

test('SMTP console URL is loaded and saved with SMTP only',async()=>{
 const {ctx,nodes,requests,view}=setup();view.smtp.console_url='https://siem.example/admin/';ctx.renderSettings(view);assert.equal(nodes.get('smtp-console-url').value,view.smtp.console_url);nodes.get('smtp-console-url').value=' https://other.example/admin/ ';await ctx.settingsAction('save-smtp');const req=requests.find(r=>r.url==='api/settings');assert.equal(req.body.smtp.console_url,'https://other.example/admin/');assert.equal(req.body.scope,'smtp');
});
