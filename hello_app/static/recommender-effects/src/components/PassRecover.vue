<template>
    <v-container class="fill-height" fluid >
    <v-row align="center" justify="center" >
        <v-col cols="12" sm="8" md="4" >
        <v-card class="elevation-12" >
            <v-toolbar color="primary" dark flat >
            <v-toolbar-title>Recommender Effects</v-toolbar-title>
            </v-toolbar>
            <v-card-text v-if="emailSending">
              <div>Enviando email...</div>
            </v-card-text>
            <v-card-text v-else-if="emailSentError">
              <div>Houve um erro ao tentar enviar o email de recuperação da senha. Por favor, tente novamente mais tarde.</div>
            </v-card-text>
            <v-card-text v-else-if="emailSent">
              <div>Se o e-mail informado estiver cadastrado no RecommenderEffects, você receberá nele uma mensagem com instruções para mudar a sua senha.</div>
            </v-card-text>
            <v-card-text v-else>
            <v-form v-on:submit.prevent v-model="valid" :lazy-validation="lazy">
                <v-text-field
                id="email"
                label="E-mail cadastrado"
                v-model="email"
                v-on:keyup="submitIfEnter" 
                :rules="emailRules"
                prepend-icon="email"
                type="text"
                required
                />
            </v-form>
            </v-card-text>
            <v-card-actions v-if="!emailSending">
            <v-spacer />
            <v-btn color="primary" @click="close"><span v-if="!emailSent">Cancelar</span><span v-else>Voltar</span></v-btn>
            <v-btn v-if="!emailSent && !emailSentError" @click="sendEmail" :disabled="!valid" color="primary">Enviar</v-btn>
            </v-card-actions>
        </v-card>
        </v-col>
    </v-row>
    </v-container>    
</template>
<script>
import { bus } from '../main'
import axios from 'axios';

export default {
  name: 'PassRecover',

  data: () => ({
    lazy: true,
    valid: true,

    emailSent: false,
    emailSentError: false,
    emailSending: false,


    email : '',
    emailRules : [
      v => !!v || 'E-mail obrigatório',
      v => /.+@.+\..+/.test(v) || 'E-mail inválido',
    ]
  }),
  methods: {
    close() {
        bus.$emit('turnOffPassRecover');
    },
    sendEmail() {
        if (this.email.indexOf('@') !== -1) {
          this.emailSending = true;
          this.emailSentError = false;
          axios.post('/passrecover', {
            email: this.email,
          })
          .then(() => {
            this.emailSent = true;
          })
          .catch((error) => {
            this.emailSentError = true;
            console.log(error);
          })
          .finally(() => this.emailSending = false);
        }
    },
    submitIfEnter(event) {
      if (event.key == 'Enter' && this.valid) {
        this.sendEmail();
      }
    }      
  }
}
</script>