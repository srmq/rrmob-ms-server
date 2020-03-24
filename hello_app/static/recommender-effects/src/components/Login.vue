<template>
    <v-container class="fill-height" fluid >
    <v-row align="center" justify="center" >
        <v-col cols="12" sm="8" md="4" >
        <v-card class="elevation-12" >
            <v-toolbar color="primary" dark flat >
            <v-toolbar-title>Recommender Effects</v-toolbar-title>
            </v-toolbar>
            <v-card-text v-if="stateChecking">
            <div>Trying to log in with Spotify state. Please wait...
            </v-card-text>
            <v-card-text v-else>
            <v-form v-model="valid" :lazy-validation="lazy">
                <span v-if="firstAccess">
                <v-text-field
                label="Nome"
                v-model="name"
                :rules="nameRules"
                prepend-icon="person"
                type="text"
                required
                />
                </span>

                <v-text-field
                label="E-mail"
                v-model="email"
                :rules="emailRules"
                prepend-icon="email"
                type="text"
                required
                />

                <v-text-field
                id="password"
                label="Senha"
                v-model="password"
                v-on:keyup="(event) => { if (!firstAccess) submitIfEnter(event); }" 
                :rules="passwordRules"
                prepend-icon="lock"
                type="password"
                required
                />
                <span v-if="firstAccess">
                <v-text-field
                id="password-check"
                label="Confirme a senha"
                v-model="passwordCheck"
                v-on:keyup="submitIfEnter"
                :rules="[passwordsOk]"
                prepend-icon="lock"
                type="password"
                required
                />
                </span>
            </v-form>
            </v-card-text>
            <v-card-actions>
            <span v-if="!firstAccess"><a v-on:click.prevent="firstAccess = true">Primeiro acesso?</a></span>
            <span v-if="firstAccess"><a v-on:click.prevent="firstAccess = false">Já tenho uma conta</a></span>            
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
  name: 'Login',

  props: ['stateLogin'],

  data: () => ({
    lazy: true,
    valid: true,
    name : '',
    nameRules : [
      v => !!v || 'Nome obrigatório',        
    ],
    email : '',
    emailRules : [
      v => !!v || 'E-mail obrigatório',
      v => /.+@.+\..+/.test(v) || 'E-mail inválido',
    ],
    password : '',
    passwordRules : [
      v => !!v || 'Senha obrigatória',
    ],
    passwordCheck : '',
    firstAccess: false,
    
    stateChecking: false,
    stateCheckError: false,
    
    errors : []
  }),
  methods: {
    passwordsOk(checkPassword) {
      if (!(checkPassword == this.password)) {
        return "As senhas não coincidem";
      }
      return true;
    },
    doSignIn() {
      axios.post('/signin', {
        email: this.email,
        password: this.password
      })
      .then((response) => {
        bus.$emit('loggedIn', {email: this.email, access_token: response.data.access_token});
      })
      .catch(function(error) {
        console.log(error);
      });
    },
    submitIfEnter(event) {
      if (event.key == 'Enter' && this.valid) {
        if (this.firstAccess) {
          //FIXME TODO signup
          console.log('do signup');
        } else {
          this.doSignIn();
        }
      }
    }
  },

  //lifecycle hooks
  created() {
    console.log("Login stateLogin received: " + this.stateLogin)
    if (this.stateLogin) {
      this.stateChecking = true;
      axios.post('/spotifystatesignin', {
        state: this.stateLogin
      })
      .then((response) => {
        bus.$emit('loggedIn', {email: response.data.email, access_token: response.data.access_token});
      })
      .catch(function(error) {
        this.stateCheckError = true;
        console.log(error);
      })
      .finally(() => this.stateChecking = false);
    }
  }
}    
</script>