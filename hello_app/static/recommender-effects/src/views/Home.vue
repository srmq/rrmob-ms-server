<template>
  <div v-if="loggedIn" class="top-view">
    <Top />
  </div>
  <div v-else class="login">
    <Login />
  </div>

</template>

<script>
// @ is an alias to /src
import Login from '@/components/Login.vue'
import Top from '@/components/Top.vue'
import { bus } from '../main'

export default {
  name: 'Home',
  components: {
    Login, Top
  },
  data: () => ({
    loggedIn: false,
    accessToken: ''
  }),
  //lifecycle hooks
  created() {
    bus.$on('loggedIn', (accessToken) => {
      this.accessToken = accessToken;
      this.loggedIn = true;
    });
    bus.$on('loggedOut', () => { this.loggedIn = false; });
  }  
}
</script>
