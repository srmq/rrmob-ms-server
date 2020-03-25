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
        <v-spacer></v-spacer>
        <v-dialog v-model="dialog" max-width="500px">
          <template v-slot:activator="{ on }">
            <v-btn color="primary" dark class="mb-2" v-on="on">New Invitee</v-btn>
          </template>
          <v-card>
            <v-card-title>
              <span class="headline">Add Invitee</span>
            </v-card-title>            

            <v-card-text>
              <v-container>
                <v-row>
                  <v-col cols="12" sm="6" md="4">
                    <v-text-field v-model="editedItem.invited_email" label="Invitee e-mail"></v-text-field>
                  </v-col>
                </v-row>
              </v-container>
            </v-card-text>

            <v-card-actions>
              <v-spacer></v-spacer>
              <v-btn color="blue darken-1" text @click="close">Cancel</v-btn>
              <v-btn color="blue darken-1" text @click="save">Save</v-btn>
            </v-card-actions>
          </v-card>
        </v-dialog>
    </v-card-title>      
      <v-data-table :item-key="id" class="elevation-1" 
                    loading="usrLoading" :items="allUsers"
                    :headers="headers" :search="search">
        <template v-slot:item.actions="{ item }">
          <v-icon
            small
            class="mr-2"
            @click="editItem(item)"
          >
            mdi-pencil
          </v-icon>
          <v-icon
            small
            @click="deleteItem(item)"
          >
            mdi-delete
          </v-icon>
        </template>
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
    editedItem : {invited_email: '', fullname: '', reg_email: '', verif_email: false},
    defaultItem : {invited_email: '', fullname: '', reg_email: '', verif_email: false},
    editedIntex: -1,
    headers: [{text: 'Invited Email', value: 'invited_email'},
              {text: 'Name', value: 'fullname'},
              {text: 'Registered Email', value: 'reg_email'},
              {text: 'Email verified?', value: 'verif_email'},
              {text: 'Actions', value: 'actions', sortable: false }
              ],
    usrLoading : true,
    usrLoadError: false,

    dialog: false
  }),

  methods: {
    close () {
      this.dialog = false;
      setTimeout(() => {
        this.editedItem = Object.assign({}, this.defaultItem)
        this.editedIndex = -1
      }, 300);
    },

    save () {
      if (this.editedIndex > -1) {
        Object.assign(this.allUsers[this.editedIndex], this.editedItem);
      } else {
        this.allUsers.push(this.editedItem);
      }
      this.close();
    },    

    editItem (item) {
      this.editedIndex = this.allUsers.indexOf(item)
      this.editedItem = Object.assign({}, item)
      this.dialog = true
    },

    deleteItem (item) {
      const index = this.allUsers.indexOf(item)
      confirm('Are you sure you want to delete this User? ALL HER DATA WILL BE LOST') && this.allUsers.splice(index, 1)
    },
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