<template>
  <div v-if="changePass" class="login">
    <ChangePass v-bind:email="email" v-bind:passchangecode="passchangecode" />
  </div>
  <div v-else-if="loggedIn" class="top-view">
    <Top v-bind:loginInfo="loginInfo"/>
  </div>
  <div v-else-if="recoverPass" class="login">
    <PassRecover />
  </div>
  <div v-else class="login">
    <Login v-bind:stateLogin="stateLogin" />
  </div>

</template>

<script>
// @ is an alias to /src
import Login from '@/components/Login.vue'
import Top from '@/components/Top.vue'
import PassRecover from '@/components/PassRecover.vue'
import ChangePass from '@/components/ChangePass.vue'

import { bus } from '../main'

export default {
  name: 'Home',
  components: {
    Login, Top, PassRecover
  },
  data: () => ({
    loggedIn: false,
    loginInfo: {},
    recoverPass: false,
    stateLogin: '',

    changePass: false,
    email: '',
    passchangecode: ''
  }),
  methods: {
    isDefined(str) {
      return !(!str || 0 === str.length);
    }
  },
  //lifecycle hooks
  created() {
    bus.$on('loggedIn', (loginInfo) => {
      this.loginInfo = loginInfo;
      this.loggedIn = true;
    });
    bus.$on('loggedOut', () => { this.loggedIn = false; });
    bus.$on('turnOffPassRecover', () => { this.recoverPass = false; });    
    bus.$on('turnOnPassRecover', () => { this.recoverPass = true; }); 
    bus.$on('turnOffChangePass', () => { this.changePass = false; });            
    this.stateLogin = this.$route.query.state;
    if (this.isDefined(this.$route.query.email) && this.isDefined(this.$route.query.passchangecode)) {
      this.email = this.$route.query.email;
      this.passchangecode = this.$route.query.passchangecode;
      this.changePass = true;
    }
    console.log('STATE: ' + this.stateLogin);
  }  
}
</script>
