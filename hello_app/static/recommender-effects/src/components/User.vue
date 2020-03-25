<template>
  <div v-if="usrLoading">
    Carregando usuários...
  </div>
  <div v-else-if="usrLoadError">
    Erro ao carregar usuários, por favor, tente novamente mais tarde.
  </div>
  <div v-else>
    Carreguei!
  </div>    
</template>

<script>
import axios from 'axios';

export default {
    name: 'User',

    props: ['rootloginInfo'],

  data: () => ({
      allUsers : null,
      usrLoading : true,
      usrLoadError: false
  }),

  methods: {

  },

  created() {
    axios.defaults.headers.common = {'Authorization': `Bearer ${this.rootloginInfo.root_token}`};
  },

  mounted() {
    axios
      .get('/loadUsers')
      .then( response => {
        this.allUsers = response.data;
        
        console.log(response);
      })
      .catch(error => {
        this.usrLoadError = true;
        console.log(error);
      })
      .finally(() => this.usrLoading = false);

  },

}
</script>