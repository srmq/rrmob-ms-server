<template>
  <div v-if="!usrLoadError">
    <v-data-table item-key="id" class="elevation-1" loading items="allUsers">  
    </v-data-table>
  </div>
  <div v-else>
    Erro ao carregar usuários, por favor, tente novamente mais tarde.
  </div>
</template>

<script>
import axios from 'axios';

export default {
    name: 'User',

    props: ['rootloginInfo'],

  data: () => ({
      allUsers : [],
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