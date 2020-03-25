<template>
    <v-container class="fill-height" fluid >
    <v-row align="center" justify="center" >
        <v-col cols="12" sm="8" md="4" >
        <v-card class="elevation-12" >
            <v-toolbar color="primary" dark flat >
            <v-toolbar-title>Recommender Effects</v-toolbar-title>
            </v-toolbar>
            <v-card-text>
            <v-form v-model="valid" :lazy-validation="lazy">
                <v-text-field
                id="password"
                label="Root password"
                v-model="password"
                v-on:keyup="(event) => { if (valid) submitIfEnter(event); }" 
                :rules="passwordRules"
                prepend-icon="lock"
                type="password"
                required
                />
            </v-form>
            </v-card-text>
            <v-card-actions>
            <v-spacer />
            <v-btn :disabled="!valid" color="primary">Entrar</v-btn>
            </v-card-actions>
        </v-card>
        </v-col>
    </v-row>
    </v-container>
</template>

<script>
import axios from 'axios';
import { bus } from '../main'

export default {
  name: 'RootLogin',

  data: () => ({
    lazy: true,
    valid: true,
    password : '',
    passwordRules : [
      v => !!v || 'Senha obrigatória',
    ],
     
    errors : []
  }),
  methods: {
    doRootSignIn() {
      console.log('root sigin called')
      axios.post('/rootsignin', {
        rootpass: this.password
      })
      .then((response) => {
        console.log('root login: success')
        bus.$emit('rootLoggedIn', {root_token: response.data.root_token});
      })
      .catch(function(error) {
        console.log(error);
      });
    },
    submitIfEnter(event) {
      if (event.key == 'Enter' && this.valid) {
        this.doRootSignIn();
      }
    }
  },
}    
</script>