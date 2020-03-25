<template>
  <div v-if="rootLoggedIn" class="top-view">
    <User v-bind:rootloginInfo="rootLoginInfo"/>
  </div>
  <div v-else class="login">
    <RootLogin />
  </div>
</template>

<script>
import { bus } from '../main'
// @ is an alias to /src
import RootLogin from '@/components/RootLogin.vue'
import User from '@/components/User.vue'

export default {
  name: 'UserMng',
  components: {
    User, RootLogin
  },
  data: () => ({
    rootLoggedIn: false,
    rootLoginInfo: {}
  }),

  //lifecycle hooks
  created() {
    bus.$on('rootLoggedIn', (rootLoginInfo) => {
      this.rootLoginInfo = rootLoginInfo;
      this.rootLoggedIn = true;
    });
    bus.$on('rootLoggedOut', () => { this.rootLoggedIn = false; });
  }  
    
}
</script>