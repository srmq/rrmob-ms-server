(function(e){function t(t){for(var n,i,s=t[0],c=t[1],l=t[2],u=0,f=[];u<s.length;u++)i=s[u],Object.prototype.hasOwnProperty.call(o,i)&&o[i]&&f.push(o[i][0]),o[i]=0;for(n in c)Object.prototype.hasOwnProperty.call(c,n)&&(e[n]=c[n]);d&&d(t);while(f.length)f.shift()();return r.push.apply(r,l||[]),a()}function a(){for(var e,t=0;t<r.length;t++){for(var a=r[t],n=!0,i=1;i<a.length;i++){var c=a[i];0!==o[c]&&(n=!1)}n&&(r.splice(t--,1),e=s(s.s=a[0]))}return e}var n={},o={app:0},r=[];function i(e){return s.p+"js/"+({about:"about",users:"users"}[e]||e)+"."+{about:"39dec791",users:"6908de86"}[e]+".js"}function s(t){if(n[t])return n[t].exports;var a=n[t]={i:t,l:!1,exports:{}};return e[t].call(a.exports,a,a.exports,s),a.l=!0,a.exports}s.e=function(e){var t=[],a=o[e];if(0!==a)if(a)t.push(a[2]);else{var n=new Promise((function(t,n){a=o[e]=[t,n]}));t.push(a[2]=n);var r,c=document.createElement("script");c.charset="utf-8",c.timeout=120,s.nc&&c.setAttribute("nonce",s.nc),c.src=i(e);var l=new Error;r=function(t){c.onerror=c.onload=null,clearTimeout(u);var a=o[e];if(0!==a){if(a){var n=t&&("load"===t.type?"missing":t.type),r=t&&t.target&&t.target.src;l.message="Loading chunk "+e+" failed.\n("+n+": "+r+")",l.name="ChunkLoadError",l.type=n,l.request=r,a[1](l)}o[e]=void 0}};var u=setTimeout((function(){r({type:"timeout",target:c})}),12e4);c.onerror=c.onload=r,document.head.appendChild(c)}return Promise.all(t)},s.m=e,s.c=n,s.d=function(e,t,a){s.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:a})},s.r=function(e){"undefined"!==typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},s.t=function(e,t){if(1&t&&(e=s(e)),8&t)return e;if(4&t&&"object"===typeof e&&e&&e.__esModule)return e;var a=Object.create(null);if(s.r(a),Object.defineProperty(a,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var n in e)s.d(a,n,function(t){return e[t]}.bind(null,n));return a},s.n=function(e){var t=e&&e.__esModule?function(){return e["default"]}:function(){return e};return s.d(t,"a",t),t},s.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},s.p="/",s.oe=function(e){throw console.error(e),e};var c=window["webpackJsonp"]=window["webpackJsonp"]||[],l=c.push.bind(c);c.push=t,c=c.slice();for(var u=0;u<c.length;u++)t(c[u]);var d=l;r.push([0,"chunk-vendors"]),a()})({0:function(e,t,a){e.exports=a("56d7")},"56d7":function(e,t,a){"use strict";a.r(t);a("e260"),a("e6cf"),a("cca6"),a("a79d");var n=a("2b0e"),o=function(){var e=this,t=e.$createElement,a=e._self._c||t;return a("v-app",[a("v-content",[a("router-view")],1)],1)},r=[],i={name:"App",data:function(){return{}}},s=i,c=a("2877"),l=a("6544"),u=a.n(l),d=a("7496"),f=a("a75b"),h=Object(c["a"])(s,o,r,!1,null,null,null),p=h.exports;u()(h,{VApp:d["a"],VContent:f["a"]});a("d3b7");var v=a("8c4f"),m=function(){var e=this,t=e.$createElement,a=e._self._c||t;return e.loggedIn?a("div",{staticClass:"top-view"},[a("Top",{attrs:{loginInfo:e.loginInfo}})],1):a("div",{staticClass:"login"},[a("Login",{attrs:{stateLogin:e.stateLogin}})],1)},g=[],b=function(){var e=this,t=e.$createElement,a=e._self._c||t;return a("v-container",{staticClass:"fill-height",attrs:{fluid:""}},[a("v-row",{attrs:{align:"center",justify:"center"}},[a("v-col",{attrs:{cols:"12",sm:"8",md:"4"}},[a("v-card",{staticClass:"elevation-12"},[a("v-toolbar",{attrs:{color:"primary",dark:"",flat:""}},[a("v-toolbar-title",[e._v("Recommender Effects")])],1),e.stateChecking?a("v-card-text",[a("div",[e._v("Trying to log in with Spotify state. Please wait... ")])]):a("v-card-text",[a("v-form",{attrs:{"lazy-validation":e.lazy},model:{value:e.valid,callback:function(t){e.valid=t},expression:"valid"}},[e.firstAccess?a("span",[a("v-text-field",{attrs:{label:"Nome",rules:e.nameRules,"prepend-icon":"person",type:"text",required:""},model:{value:e.name,callback:function(t){e.name=t},expression:"name"}})],1):e._e(),a("v-text-field",{attrs:{label:"E-mail",rules:e.emailRules,"prepend-icon":"email",type:"text",required:""},model:{value:e.email,callback:function(t){e.email=t},expression:"email"}}),a("v-text-field",{attrs:{id:"password",label:"Senha",rules:e.passwordRules,"prepend-icon":"lock",type:"password",required:""},on:{keyup:function(t){e.firstAccess||e.submitIfEnter(t)}},model:{value:e.password,callback:function(t){e.password=t},expression:"password"}}),e.firstAccess?a("span",[a("v-text-field",{attrs:{id:"password-check",label:"Confirme a senha",rules:[e.passwordsOk],"prepend-icon":"lock",type:"password",required:""},on:{keyup:e.submitIfEnter},model:{value:e.passwordCheck,callback:function(t){e.passwordCheck=t},expression:"passwordCheck"}})],1):e._e()],1)],1),a("v-card-actions",[e.firstAccess?e._e():a("span",[a("a",{on:{click:function(t){t.preventDefault(),e.firstAccess=!0}}},[e._v("Primeiro acesso?")])]),e.firstAccess?a("span",[a("a",{on:{click:function(t){t.preventDefault(),e.firstAccess=!1}}},[e._v("Já tenho uma conta")])]):e._e(),a("v-spacer"),a("v-btn",{attrs:{disabled:!e.valid,color:"primary"}},[e._v("Entrar")])],1)],1)],1)],1)],1)},y=[],k=a("bc3a"),w=a.n(k),C={name:"Login",props:["stateLogin"],data:function(){return{lazy:!0,valid:!0,name:"",nameRules:[function(e){return!!e||"Nome obrigatório"}],email:"",emailRules:[function(e){return!!e||"E-mail obrigatório"},function(e){return/.+@.+\..+/.test(e)||"E-mail inválido"}],password:"",passwordRules:[function(e){return!!e||"Senha obrigatória"}],passwordCheck:"",firstAccess:!1,stateChecking:!1,stateCheckError:!1,errors:[]}},methods:{passwordsOk:function(e){return e==this.password||"As senhas não coincidem"},doSignIn:function(){var e=this;w.a.post("/signin",{email:this.email,password:this.password}).then((function(t){Y.$emit("loggedIn",{email:e.email,access_token:t.data.access_token})})).catch((function(e){console.log(e)}))},submitIfEnter:function(e){"Enter"==e.key&&this.valid&&(this.firstAccess?console.log("do signup"):this.doSignIn())}},created:function(){var e=this;console.log("Login stateLogin received: "+this.stateLogin),this.stateLogin&&(this.stateChecking=!0,w.a.post("/spotifystatesignin",{state:this.stateLogin}).then((function(e){Y.$emit("loggedIn",{email:e.data.email,access_token:e.data.access_token})})).catch((function(e){this.stateCheckError=!0,console.log(e)})).finally((function(){return e.stateChecking=!1})))}},_=C,E=a("8336"),x=a("b0af"),A=a("99d9"),L=a("62ad"),V=a("a523"),O=a("4bd4"),T=a("0fd9"),I=a("2fa4"),S=a("8654"),j=a("71d9"),P=a("2a7f"),U=Object(c["a"])(_,b,y,!1,null,null,null),R=U.exports;u()(U,{VBtn:E["a"],VCard:x["a"],VCardActions:A["a"],VCardText:A["b"],VCol:L["a"],VContainer:V["a"],VForm:O["a"],VRow:T["a"],VSpacer:I["a"],VTextField:S["a"],VToolbar:j["a"],VToolbarTitle:P["a"]});var M=function(){var e=this,t=e.$createElement,a=e._self._c||t;return a("v-container",{staticClass:"fill-height",attrs:{fluid:""}},[a("v-row",{staticClass:"text-center"},[a("v-col",{staticClass:"mb-4"},[a("h1",{staticClass:"display-2 font-weight-bold mb-3"},[e._v(" Bem-vindo(a) ao Recommender Effects! ")]),e.errored?a("div",[a("p",{staticClass:"subheading font-weight-regular"},[e._v(" Houve um erro de carregamento do sistema. Por favor, tente novamente mais tarde. ")])]):e.loading?a("div",[a("p",{staticClass:"subheading font-weight-regular"},[e._v(" Carregando... ")])]):e.isEmailVerified?a("div",[e.authLoadError?a("div",[a("p",{staticClass:"subheading font-weight-regular"},[e._v(" Houve um erro ao carregar informações de autenticação. Por favor, tente novamente mais tarde. ")])]):e.authLoading?a("div",[a("p",{staticClass:"subheading font-weight-regular"},[e._v(" Carregando informações de autenticação... ")])]):a("div",[e.authChecking?a("div",[e._v(" Checando informações de autenticação... ")]):e.authCheckError?a("div",[e._v(" Erro ao checar autenticação com Spotify. Por favor tente novamente mais tarde. ")]):e.authValid?a("div",[e._v(" Obrigado! Você já está participando do nosso experimento. Aguarde novidades! ")]):a("div",[e.authUrlLoading?a("div",[e._v(" "+e._s(e.authUrlMessage())+" ")]):e.authUrlErrored?a("div",[e._v(" Erro ao carregar URL de autenticação. Por favor tente novamente mais tarde... ")]):a("div",[e._v(" Por favor, acesse "),a("a",{attrs:{href:e.authUrl}},[e._v("este link")]),e._v(" para conceder autorização ao Recommender Effects para acessar suas informações no Spotify. Os dados acessados serão utilizados exclusivamente no contexto do experimento. ")])])])]):a("div",[a("p",{staticClass:"subheading font-weight-regular"},[e._v(" Foi-lhe enviada uma mensagem de verificação para seu endereço de e-mail informado. Por favor, clique no link da mensagem para confirmar o seu endereço. Caso não receba a mensagem, clique neste link FIXME para enviarmos novamente. ")])])])],1)],1)},$=[],q={name:"Top",props:["loginInfo"],data:function(){return{loading:!0,errored:!1,isEmailVerified:null,authLoading:!0,authAccessToken:null,authLoadError:!1,authChecking:!0,authValid:!1,authCheckError:!1,authUrlLoading:!0,authUrlErrored:!1,authUrl:""}},methods:{verifySpotifyAuth:function(){var e=this;if(null==this.authAccessToken)this.authChecking=!1,this.authValid=!1,this.authCheckError=!1;else{this.authChecking=!0;var t=w.a.create({headers:{common:{Authorization:"Bearer "+this.authAccessToken}}});t.get("https://api.spotify.com/v1/me").then((function(t){t.data&&"email"in t.data?e.authValid=!0:e.authValid=!1,console.log(t.data)})).catch((function(t){e.authCheckError=!0,console.log(t)})).finally((function(){return e.authChecking=!1}))}},getMySpotifyAuth:function(){var e=this;w.a.get("/getmyspotifyaccesstoken").then((function(t){null!=t.data&&"access_token"in t.data&&(e.authAccessToken=t.data.access_token),console.log(t),e.verifySpotifyAuth()})).catch((function(t){e.authLoadError=!0,console.log(t)})).finally((function(){return e.authLoading=!1}))},authUrlMessage:function(){var e=this;return w.a.get("/spotauthorize").then((function(t){"url"in t.data&&(e.authUrl=t.data.url)})).catch((function(t){e.authUrlErrored=!0,console.log(t)})).finally((function(){return e.authUrlLoading=!1})),"Carregando URL de autenticação..."}},created:function(){w.a.defaults.headers.common={Authorization:"Bearer ".concat(this.loginInfo.access_token)}},mounted:function(){var e=this;w.a.get("/isemailverified").then((function(t){e.isEmailVerified=t.data.result,e.isEmailVerified&&e.getMySpotifyAuth()})).catch((function(t){console.log(t),e.errored=!0})).finally((function(){return e.loading=!1}))}},z=q,B=Object(c["a"])(z,M,$,!1,null,null,null),F=B.exports;u()(B,{VCol:L["a"],VContainer:V["a"],VRow:T["a"]});var H={name:"Home",components:{Login:R,Top:F},data:function(){return{loggedIn:!1,loginInfo:{},stateLogin:""}},created:function(){var e=this;Y.$on("loggedIn",(function(t){e.loginInfo=t,e.loggedIn=!0})),Y.$on("loggedOut",(function(){e.loggedIn=!1})),this.stateLogin=this.$route.query.state,console.log("STATE: "+this.stateLogin)}},J=H,D=Object(c["a"])(J,m,g,!1,null,null,null),N=D.exports;n["a"].use(v["a"]);var X=[{path:"/",name:"Home",component:N},{path:"/about",name:"About",component:function(){return a.e("about").then(a.bind(null,"f820"))}},{path:"/users",name:"UserMng",component:function(){return a.e("users").then(a.bind(null,"5152"))}}],G=new v["a"]({mode:"history",base:"/",routes:X}),K=G,Q=a("f309");n["a"].use(Q["a"]);var W=new Q["a"]({icons:{iconfont:"mdiSvg"}});a("d1e78");a.d(t,"bus",(function(){return Y}));var Y=new n["a"];n["a"].config.productionTip=!1,new n["a"]({router:K,vuetify:W,render:function(e){return e(p)}}).$mount("#app")}});
//# sourceMappingURL=app.834524c0.js.map