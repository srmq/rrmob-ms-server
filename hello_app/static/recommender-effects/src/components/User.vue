<template>
  <div v-if="!usrLoadError">
    <v-card>
      <v-card-title>
        Users
        <v-spacer></v-spacer>
        <v-text-field
          v-model="search"
          append-icon="mdi-magnify"
          label="Search"
          single-line
          hide-details
        ></v-text-field>
    </v-card-title>      
      <v-data-table :item-key="id" class="elevation-1" 
                    loading="usrLoading" :items="allUsers"
                    :headers="headers" :search="search">  
      </v-data-table>
    </v-card>
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
    search: '',
    allUsers : [],
    headers: [{text: 'Invited Email', value: 'invited_email'},
              {text: 'Name', value: 'fullname'},
              {text: 'Registered Email', value: 'reg_email'},
              {text: 'Email verified?', value: 'verif_email'}
              ],
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