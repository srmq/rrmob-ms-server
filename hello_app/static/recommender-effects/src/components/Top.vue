<template>
    <v-container class="fill-height" fluid >
      <v-row class="text-center">
        <v-col class="mb-4">
          <h1 class="display-2 font-weight-bold mb-3">
            Bem-vindo(a) ao Recommender Effects!
          </h1>

          <div v-if="!isEmailVerified()">
            <p  class="subheading font-weight-regular">
              Foi-lhe enviada uma mensagem de verificação para seu endereço de e-mail
              informado. Por favor, clique no link da mensagem para confirmar o seu 
              endereço. Caso não receba a mensagem, clique neste link FIXME para enviarmos 
              novamente.
            </p>
          </div>
        </v-col>
      </v-row>
    </v-container>
</template>

<script>
import axios from 'axios';

export default {
  name: 'Top',

  props: ['loginInfo'],

  data: () => ({
    // TODO
  }),

  created() {
    axios.defaults.headers.common = {'Authorization': `Bearer ${this.loginInfo.access_token}`};
  },

  methods: {
    isEmailVerified() {
      axios.get('/isemailverified')
        .then(function (response) {
          console.log(response);          
          return response.data.result;
        })
        .catch(function (error) {
          console.log(error);
          return false;
        });
    }
  }    
}
</script>