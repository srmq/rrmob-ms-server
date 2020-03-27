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
              <span class="headline">Invitee</span>
            </v-card-title>            

            <v-card-text>
              <v-container>
                <v-row v-if="editedItem.fullname.length >= 2 && editedItem.reg_email.indexOf('@') != -1">
                  <v-col cols="12" sm="6" md="4">
                    <v-text-field v-model="editedItem.invited_email" label="Invitee e-mail"></v-text-field>
                  </v-col>
                  <v-col cols="12" sm="6" md="4">
                    <v-text-field v-model="editedItem.fullname" label="Full name"></v-text-field>
                  </v-col>
                  <v-col cols="12" sm="6" md="4">
                    <v-text-field v-model="editedItem.reg_email" label="Registered e-mail"></v-text-field>
                  </v-col>
                </v-row>
                <v-row v-else>
                  <v-col cols="12" sm="12" md="8">
                    <v-text-field v-model="editedItem.invited_email" label="Invitee e-mail"></v-text-field>
                  </v-col>
                </v-row>
              </v-container>
            </v-card-text>

            <v-card-actions>
              <v-spacer></v-spacer>
              <v-btn color="blue darken-1" :disabled="isUpdating" text @click="close">Cancel</v-btn>
              <v-btn color="blue darken-1" :disabled="isUpdating" text @click="save">Save</v-btn>
            </v-card-actions>
          </v-card>
          <div>
              <v-alert
                v-model="addInviteeAlert"
                type="error"
                close-text="Close"
                dismissible
              >
                {{ addInviteeAlertMsg }}
              </v-alert>
          </div>          
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

    dialog: false,
    addInviteeAlert: false,
    addInviteeAlertMsg: '',

    isUpdating: false
  }),

  methods: {
    close () {
      this.dialog = false;
      setTimeout(() => {
        this.editedItem = Object.assign({}, this.defaultItem);
        this.editedIndex = -1;
      }, 300);
    },

    //will use a write-through strategy, change in array only after it is changed
    //successfully in bd
    save () {
      if (this.editedIndex > -1) {
        //editing an existing user
        this.isUpdating = true;
        axios.post('/updateUser', this.editedItem)
        .then(() => {
          Object.assign(this.allUsers[this.editedIndex], this.editedItem);
          this.close();
        })
        .catch(function(error) {
          console.log(error);
          this.addInviteeAlertMsg = "An unexpected error has ocurred";
          if (error.response) {
            if (error.response.data) {
              if (error.response.data.msg) {
                this.addInviteeAlertMsg = error.response.data.msg;
              }
            }
          }          
          this.addInviteeAlert = true;
        })
        .finally(() => this.isUpdating = false);
      } else {
        //is a new invitee
        this.isUpdating = true;
        axios.put('/addinvitee', {
          email: this.editedItem.invited_email
        })
        .then((response) => {
          this.editedItem.id = response.data.id;
          this.allUsers.push(this.editedItem);
          this.close();
        })
        .catch(function(error) {
          console.log(error);
          this.addInviteeAlertMsg = "An unexpected error has ocurred";
          if (error.response) {
            if (error.response.data) {
              if (error.response.data.msg) {
                this.addInviteeAlertMsg = error.response.data.msg;
              }
            }
          }          
          this.addInviteeAlert = true;
        })
        .finally(() => this.isUpdating = false);
      }
    },    

    editItem (item) {
      this.editedIndex = this.allUsers.indexOf(item);
      this.editedItem = Object.assign({}, item);
      this.dialog = true;
    },

    deleteItem (item) {
      const index = this.allUsers.indexOf(item);
      confirm('Are you sure you want to delete this User? ALL HER DATA WILL BE LOST') && this.allUsers.splice(index, 1);
    },

    loadFromServer() {
      this.usrLoadError = false;
      this.usrLoading = true;
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
    }
  },

  created() {
    axios.defaults.headers.common = {'Authorization': `Bearer ${this.rootloginInfo.root_token}`};
  },

  mounted() {
    this.loadFromServer();
  },

}
</script>