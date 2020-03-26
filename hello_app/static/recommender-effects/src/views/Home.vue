<template>
  <div v-if="loggedIn" class="top-view">
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
    stateLogin: ''
  }),
  //lifecycle hooks
  created() {
    bus.$on('loggedIn', (loginInfo) => {
      this.loginInfo = loginInfo;
      this.loggedIn = true;
    });
    bus.$on('loggedOut', () => { this.loggedIn = false; });
    bus.$on('turnOffPassRecover', () => { this.recoverPass = false; });    
    bus.$on('turnOnPassRecover', () => { this.recoverPass = true; });        
    this.stateLogin = this.$route.query.state;
    console.log('STATE: ' + this.stateLogin);
  }  
}
</script>
