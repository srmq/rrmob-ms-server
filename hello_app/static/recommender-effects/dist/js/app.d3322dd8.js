(function(e){function t(t){for(var n,r,s=t[0],c=t[1],l=t[2],u=0,d=[];u<s.length;u++)r=s[u],Object.prototype.hasOwnProperty.call(o,r)&&o[r]&&d.push(o[r][0]),o[r]=0;for(n in c)Object.prototype.hasOwnProperty.call(c,n)&&(e[n]=c[n]);f&&f(t);while(d.length)d.shift()();return i.push.apply(i,l||[]),a()}function a(){for(var e,t=0;t<i.length;t++){for(var a=i[t],n=!0,r=1;r<a.length;r++){var s=a[r];0!==o[s]&&(n=!1)}n&&(i.splice(t--,1),e=c(c.s=a[0]))}return e}var n={},r={app:0},o={app:0},i=[];function s(e){return c.p+"js/"+({about:"about",users:"users"}[e]||e)+"."+{about:"39dec791",users:"be607b06"}[e]+".js"}function c(t){if(n[t])return n[t].exports;var a=n[t]={i:t,l:!1,exports:{}};return e[t].call(a.exports,a,a.exports,c),a.l=!0,a.exports}c.e=function(e){var t=[],a={users:1};r[e]?t.push(r[e]):0!==r[e]&&a[e]&&t.push(r[e]=new Promise((function(t,a){for(var n="css/"+({about:"about",users:"users"}[e]||e)+"."+{about:"31d6cfe0",users:"fba160a8"}[e]+".css",o=c.p+n,i=document.getElementsByTagName("link"),s=0;s<i.length;s++){var l=i[s],u=l.getAttribute("data-href")||l.getAttribute("href");if("stylesheet"===l.rel&&(u===n||u===o))return t()}var d=document.getElementsByTagName("style");for(s=0;s<d.length;s++){l=d[s],u=l.getAttribute("data-href");if(u===n||u===o)return t()}var f=document.createElement("link");f.rel="stylesheet",f.type="text/css",f.onload=t,f.onerror=function(t){var n=t&&t.target&&t.target.src||o,i=new Error("Loading CSS chunk "+e+" failed.\n("+n+")");i.code="CSS_CHUNK_LOAD_FAILED",i.request=n,delete r[e],f.parentNode.removeChild(f),a(i)},f.href=o;var v=document.getElementsByTagName("head")[0];v.appendChild(f)})).then((function(){r[e]=0})));var n=o[e];if(0!==n)if(n)t.push(n[2]);else{var i=new Promise((function(t,a){n=o[e]=[t,a]}));t.push(n[2]=i);var l,u=document.createElement("script");u.charset="utf-8",u.timeout=120,c.nc&&u.setAttribute("nonce",c.nc),u.src=s(e);var d=new Error;l=function(t){u.onerror=u.onload=null,clearTimeout(f);var a=o[e];if(0!==a){if(a){var n=t&&("load"===t.type?"missing":t.type),r=t&&t.target&&t.target.src;d.message="Loading chunk "+e+" failed.\n("+n+": "+r+")",d.name="ChunkLoadError",d.type=n,d.request=r,a[1](d)}o[e]=void 0}};var f=setTimeout((function(){l({type:"timeout",target:u})}),12e4);u.onerror=u.onload=l,document.head.appendChild(u)}return Promise.all(t)},c.m=e,c.c=n,c.d=function(e,t,a){c.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:a})},c.r=function(e){"undefined"!==typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},c.t=function(e,t){if(1&t&&(e=c(e)),8&t)return e;if(4&t&&"object"===typeof e&&e&&e.__esModule)return e;var a=Object.create(null);if(c.r(a),Object.defineProperty(a,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var n in e)c.d(a,n,function(t){return e[t]}.bind(null,n));return a},c.n=function(e){var t=e&&e.__esModule?function(){return e["default"]}:function(){return e};return c.d(t,"a",t),t},c.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},c.p="/",c.oe=function(e){throw console.error(e),e};var l=window["webpackJsonp"]=window["webpackJsonp"]||[],u=l.push.bind(l);l.push=t,l=l.slice();for(var d=0;d<l.length;d++)t(l[d]);var f=u;i.push([0,"chunk-vendors"]),a()})({0:function(e,t,a){e.exports=a("56d7")},"56d7":function(e,t,a){"use strict";a.r(t);a("e260"),a("e6cf"),a("cca6"),a("a79d");var n=a("2b0e"),r=function(){var e=this,t=e.$createElement,a=e._self._c||t;return a("v-app",[a("v-content",[a("router-view")],1)],1)},o=[],i={name:"App",data:function(){return{}}},s=i,c=a("2877"),l=a("6544"),u=a.n(l),d=a("7496"),f=a("a75b"),v=Object(c["a"])(s,r,o,!1,null,null,null),m=v.exports;u()(v,{VApp:d["a"],VContent:f["a"]});a("d3b7");var h=a("8c4f"),p=function(){var e=this,t=e.$createElement,a=e._self._c||t;return e.loggedIn?a("div",{staticClass:"top-view"},[a("Top",{attrs:{loginInfo:e.loginInfo}})],1):e.recoverPass?a("div",{staticClass:"login"},[a("PassRecover")],1):a("div",{staticClass:"login"},[a("Login",{attrs:{stateLogin:e.stateLogin}})],1)},g=[],b=function(){var e=this,t=e.$createElement,a=e._self._c||t;return a("v-container",{staticClass:"fill-height",attrs:{fluid:""}},[a("v-row",{attrs:{align:"center",justify:"center"}},[a("v-col",{attrs:{cols:"12",sm:"8",md:"4"}},[a("v-card",{staticClass:"elevation-12"},[a("v-toolbar",{attrs:{color:"primary",dark:"",flat:""}},[a("v-toolbar-title",[e._v("Recommender Effects")])],1),e.stateChecking?a("v-card-text",[a("div",[e._v("Trying to log in with Spotify state. Please wait... ")])]):a("v-card-text",[a("v-form",{attrs:{"lazy-validation":e.lazy},model:{value:e.valid,callback:function(t){e.valid=t},expression:"valid"}},[e.firstAccess?a("span",[a("v-text-field",{attrs:{label:"Nome",rules:e.nameRules,"prepend-icon":"person",type:"text",required:""},model:{value:e.name,callback:function(t){e.name=t},expression:"name"}})],1):e._e(),a("v-text-field",{attrs:{label:"E-mail",rules:e.emailRules,"prepend-icon":"email",type:"text",required:""},model:{value:e.email,callback:function(t){e.email=t},expression:"email"}}),a("v-text-field",{attrs:{id:"password",label:"Senha",rules:e.passwordRules,"prepend-icon":"lock",type:"password",required:""},on:{keyup:function(t){e.firstAccess||e.submitIfEnter(t)}},model:{value:e.password,callback:function(t){e.password=t},expression:"password"}}),e.firstAccess?a("span",[a("v-text-field",{attrs:{id:"password-check",label:"Confirme a senha",rules:[e.passwordsOk],"prepend-icon":"lock",type:"password",required:""},on:{keyup:e.submitIfEnter},model:{value:e.passwordCheck,callback:function(t){e.passwordCheck=t},expression:"passwordCheck"}})],1):e._e()],1)],1),a("v-card-actions",[a("v-btn",{attrs:{disabled:!e.valid,color:"primary"}},[e._v("Entrar")])],1)],1)],1)],1),e.firstAccess?e._e():a("v-row",{attrs:{align:"center",justify:"center"}},[a("v-col",{attrs:{cols:"6",sm:"4",md:"2"}},[a("a",{on:{click:function(t){t.preventDefault(),e.firstAccess=!0}}},[e._v("Primeiro acesso?")])]),a("v-col",{attrs:{cols:"6",sm:"4",md:"2"}},[a("a",{on:{click:function(t){return t.preventDefault(),e.forgotPass()}}},[e._v("Esqueceu a senha?")])])],1),e.firstAccess?a("v-row",{attrs:{align:"center",justify:"center"}},[a("v-col",{attrs:{cols:"12",sm:"8",md:"4"}},[a("a",{on:{click:function(t){t.preventDefault(),e.firstAccess=!1}}},[e._v("Já tenho uma conta")])])],1):e._e()],1)},y=[],k=(a("b0c0"),a("bc3a")),C=a.n(k),w={name:"Login",props:["stateLogin"],data:function(){return{lazy:!0,valid:!0,name:"",nameRules:[function(e){return!!e||"Nome obrigatório"}],email:"",emailRules:[function(e){return!!e||"E-mail obrigatório"},function(e){return/.+@.+\..+/.test(e)||"E-mail inválido"}],password:"",passwordRules:[function(e){return!!e||"Senha obrigatória"}],passwordCheck:"",firstAccess:!1,stateChecking:!1,stateCheckError:!1,errors:[]}},methods:{passwordsOk:function(e){return e==this.password||"As senhas não coincidem"},doSignIn:function(){var e=this;C.a.post("/signin",{email:this.email,password:this.password}).then((function(t){re.$emit("loggedIn",{email:e.email,access_token:t.data.access_token})})).catch((function(e){console.log(e)}))},submitIfEnter:function(e){var t=this;"Enter"==e.key&&this.valid&&(this.firstAccess?C.a.post("/signup",{fullname:this.name,emailaddr:this.email,password:this.password}).then((function(){t.doSignIn()})).catch((function(e){console.log(e)})):this.doSignIn())},forgotPass:function(){re.$emit("turnOnPassRecover")}},created:function(){var e=this;console.log("Login stateLogin received: "+this.stateLogin),this.stateLogin&&(this.stateChecking=!0,C.a.post("/spotifystatesignin",{state:this.stateLogin}).then((function(e){re.$emit("loggedIn",{email:e.data.email,access_token:e.data.access_token})})).catch((function(e){this.stateCheckError=!0,console.log(e)})).finally((function(){return e.stateChecking=!1})))}},_=w,E=a("8336"),x=a("b0af"),V=a("99d9"),A=a("62ad"),P=a("a523"),L=a("4bd4"),T=a("0fd9"),O=a("8654"),R=a("71d9"),S=a("2a7f"),I=Object(c["a"])(_,b,y,!1,null,null,null),j=I.exports;u()(I,{VBtn:E["a"],VCard:x["a"],VCardActions:V["a"],VCardText:V["b"],VCol:A["a"],VContainer:P["a"],VForm:L["a"],VRow:T["a"],VTextField:O["a"],VToolbar:R["a"],VToolbarTitle:S["a"]});var U=function(){var e=this,t=e.$createElement,a=e._self._c||t;return a("v-container",{staticClass:"fill-height",attrs:{fluid:""}},[a("v-row",{staticClass:"text-center"},[a("v-col",{staticClass:"mb-4"},[a("h1",{staticClass:"display-2 font-weight-bold mb-3"},[e._v(" Bem-vindo(a) ao Recommender Effects! ")]),e.errored?a("div",[a("p",{staticClass:"subheading font-weight-regular"},[e._v(" Houve um erro de carregamento do sistema. Por favor, tente novamente mais tarde. ")])]):e.loading?a("div",[a("p",{staticClass:"subheading font-weight-regular"},[e._v(" Carregando... ")])]):e.isEmailVerified?a("div",[e.authLoadError?a("div",[a("p",{staticClass:"subheading font-weight-regular"},[e._v(" Houve um erro ao carregar informações de autenticação. Por favor, tente novamente mais tarde. ")])]):e.authLoading?a("div",[a("p",{staticClass:"subheading font-weight-regular"},[e._v(" Carregando informações de autenticação... ")])]):a("div",[e.authChecking?a("div",[e._v(" Checando informações de autenticação... ")]):e.authCheckError?a("div",[e._v(" Erro ao checar autenticação com Spotify. Por favor tente novamente mais tarde. ")]):e.authValid?a("div",[e._v(" Obrigado! Você já está participando do nosso experimento. Aguarde novidades! ")]):a("div",[e.authUrlLoading?a("div",[e._v(" "+e._s(e.authUrlMessage())+" ")]):e.authUrlErrored?a("div",[e._v(" Erro ao carregar URL de autenticação. Por favor tente novamente mais tarde... ")]):a("div",[e._v(" Por favor, acesse "),a("a",{attrs:{href:e.authUrl}},[e._v("este link")]),e._v(" para conceder autorização ao Recommender Effects para acessar suas informações no Spotify. Os dados acessados serão utilizados exclusivamente no contexto do experimento. ")])])])]):a("div",[e.resendEmail?a("div",[a("p",{staticClass:"subheading font-weight-regular"},[e._v(" Foi-lhe enviada uma mensagem de verificação para seu endereço de e-mail informado. Por favor, clique no link da mensagem que recebeu para confirmar o seu endereço. Caso não receba a mensagem, clique "),a("a",{attrs:{href:"#"},on:{click:e.sendConfirmation}},[e._v("neste link")]),e._v(" para enviarmos novamente. ")])]):a("div",[e._v(" Foi-lhe novamente enviada uma mensagem de verificação para seu endereço de e-mail informado. Por favor, clique no link da mensagem que recebeu para confirmar o seu endereço. ")])])])],1)],1)},$=[],q={name:"Top",props:["loginInfo"],data:function(){return{loading:!0,errored:!1,isEmailVerified:null,authLoading:!0,authAccessToken:null,authLoadError:!1,authChecking:!0,authValid:!1,authCheckError:!1,authUrlLoading:!0,authUrlErrored:!1,authUrl:"",resendEmail:!0}},methods:{verifySpotifyAuth:function(){var e=this;if(null==this.authAccessToken)this.authChecking=!1,this.authValid=!1,this.authCheckError=!1;else{this.authChecking=!0;var t=C.a.create({headers:{common:{Authorization:"Bearer "+this.authAccessToken}}});t.get("https://api.spotify.com/v1/me").then((function(t){t.data&&"email"in t.data?e.authValid=!0:e.authValid=!1,console.log(t.data)})).catch((function(t){e.authCheckError=!0,console.log(t)})).finally((function(){return e.authChecking=!1}))}},getMySpotifyAuth:function(){var e=this;C.a.get("/getmyspotifyaccesstoken").then((function(t){null!=t.data&&"access_token"in t.data&&(e.authAccessToken=t.data.access_token),console.log(t),e.verifySpotifyAuth()})).catch((function(t){e.authLoadError=!0,console.log(t)})).finally((function(){return e.authLoading=!1}))},authUrlMessage:function(){var e=this;return C.a.get("/spotauthorize").then((function(t){"url"in t.data&&(e.authUrl=t.data.url)})).catch((function(t){e.authUrlErrored=!0,console.log(t)})).finally((function(){return e.authUrlLoading=!1})),"Carregando URL de autenticação..."},sendConfirmation:function(){var e=this;C.a.post("/resendconfirmationemail",{}).catch((function(e){console.log(e)})).finally((function(){return e.resendEmail=!1}))}},created:function(){C.a.defaults.headers.common={Authorization:"Bearer ".concat(this.loginInfo.access_token)}},mounted:function(){var e=this;C.a.get("/isemailverified").then((function(t){e.isEmailVerified=t.data.result,e.isEmailVerified&&e.getMySpotifyAuth()})).catch((function(t){console.log(t),e.errored=!0})).finally((function(){return e.loading=!1}))}},z=q,M=Object(c["a"])(z,U,$,!1,null,null,null),B=M.exports;u()(M,{VCol:A["a"],VContainer:P["a"],VRow:T["a"]});var F=function(){var e=this,t=e.$createElement,a=e._self._c||t;return a("v-container",{staticClass:"fill-height",attrs:{fluid:""}},[a("v-row",{attrs:{align:"center",justify:"center"}},[a("v-col",{attrs:{cols:"12",sm:"8",md:"4"}},[a("v-card",{staticClass:"elevation-12"},[a("v-toolbar",{attrs:{color:"primary",dark:"",flat:""}},[a("v-toolbar-title",[e._v("Recommender Effects")])],1),a("v-card-text",[a("v-form",{attrs:{"lazy-validation":e.lazy},on:{submit:function(e){e.preventDefault()}},model:{value:e.valid,callback:function(t){e.valid=t},expression:"valid"}},[a("v-text-field",{attrs:{id:"email",label:"E-mail cadastrado",rules:e.emailRules,"prepend-icon":"email",type:"text",required:""},on:{keyup:e.submitIfEnter},model:{value:e.email,callback:function(t){e.email=t},expression:"email"}})],1)],1),a("v-card-actions",[a("v-spacer"),a("v-btn",{attrs:{color:"primary"},on:{click:e.close}},[e._v("Cancelar")]),a("v-btn",{attrs:{disabled:!e.valid,color:"primary"}},[e._v("Enviar")])],1)],1)],1)],1)],1)},N=[],D={name:"PassRecover",data:function(){return{lazy:!0,valid:!0,email:"",emailRules:[function(e){return!!e||"E-mail obrigatório"},function(e){return/.+@.+\..+/.test(e)||"E-mail inválido"}]}},methods:{close:function(){re.$emit("turnOffPassRecover")},submitIfEnter:function(e){"Enter"==e.key&&this.valid}}},H=D,J=a("2fa4"),K=Object(c["a"])(H,F,N,!1,null,null,null),G=K.exports;u()(K,{VBtn:E["a"],VCard:x["a"],VCardActions:V["a"],VCardText:V["b"],VCol:A["a"],VContainer:P["a"],VForm:L["a"],VRow:T["a"],VSpacer:J["a"],VTextField:O["a"],VToolbar:R["a"],VToolbarTitle:S["a"]});var Q={name:"Home",components:{Login:j,Top:B,PassRecover:G},data:function(){return{loggedIn:!1,loginInfo:{},recoverPass:!1,stateLogin:""}},created:function(){var e=this;re.$on("loggedIn",(function(t){e.loginInfo=t,e.loggedIn=!0})),re.$on("loggedOut",(function(){e.loggedIn=!1})),re.$on("turnOffPassRecover",(function(){e.recoverPass=!1})),re.$on("turnOnPassRecover",(function(){e.recoverPass=!0})),this.stateLogin=this.$route.query.state,console.log("STATE: "+this.stateLogin)}},W=Q,X=Object(c["a"])(W,p,g,!1,null,null,null),Y=X.exports;n["a"].use(h["a"]);var Z=[{path:"/",name:"Home",component:Y},{path:"/about",name:"About",component:function(){return a.e("about").then(a.bind(null,"f820"))}},{path:"/users",name:"UserMng",component:function(){return a.e("users").then(a.bind(null,"5152"))}}],ee=new h["a"]({mode:"history",base:"/",routes:Z}),te=ee,ae=a("f309");n["a"].use(ae["a"]);var ne=new ae["a"]({icons:{iconfont:"mdiSvg"}});a("d1e78");a.d(t,"bus",(function(){return re}));var re=new n["a"];n["a"].config.productionTip=!1,new n["a"]({router:te,vuetify:ne,render:function(e){return e(m)}}).$mount("#app")}});
//# sourceMappingURL=app.d3322dd8.js.map