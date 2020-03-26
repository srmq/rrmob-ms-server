<template>
    <v-container class="fill-height" fluid >
    <v-row align="center" justify="center" >
        <v-col cols="12" sm="8" md="4" >
        <v-card class="elevation-12" >
            <v-toolbar color="primary" dark flat >
            <v-toolbar-title>Recommender Effects</v-toolbar-title>
            </v-toolbar>
            <v-card-text>
            <v-form v-on:submit.prevent v-model="valid" :lazy-validation="lazy">
                <v-text-field
                id="email"
                label="E-mail cadastrado"
                v-model="email"
                v-on:keyup="submitIfEnter" 
                :rules="email"
                prepend-icon="email"
                type="text"
                required
                />
            </v-form>
            </v-card-text>
            <v-card-actions>
            <v-spacer />
            <v-btn color="primary" @click="close">Cancelar</v-btn>
            <v-btn :disabled="!valid" color="primary">Enviar</v-btn>
            </v-card-actions>
        </v-card>
        </v-col>
    </v-row>
    </v-container>    
</template>
<script>
import { bus } from '../main'

export default {
  name: 'PassRecover',

  data: () => ({
    lazy: true,
    valid: false,

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
    submitIfEnter(event) {
      if (event.key == 'Enter' && this.valid) {
        //FIXME TODO
      }
    }      
  }
}
</script>