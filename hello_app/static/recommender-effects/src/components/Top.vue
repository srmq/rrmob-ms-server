<template>
    <v-container class="fill-height" fluid >
      <v-row class="text-center">
        <v-col class="mb-4">
          <h1 class="display-2 font-weight-bold mb-3">
            Bem-vindo(a) ao Recommender Effects!
          </h1>

          <div v-if="errored">
            <p  class="subheading font-weight-regular">
              Houve um erro de carregamento do sistema. Por favor, tente novamente mais tarde.
            </p>
          </div>
          <div v-else-if="loading">
            <p  class="subheading font-weight-regular">
              Carregando...
            </p>
          </div>
          <div v-else-if="!isEmailVerified">
            <p  class="subheading font-weight-regular">
              Foi-lhe enviada uma mensagem de verificação para seu endereço de e-mail
               informado. Por favor, clique no link da mensagem para confirmar o seu
               endereço. Caso não receba a mensagem, clique neste link FIXME para enviarmos
               novamente.
            </p>
          </div>
          <div v-else>
            <!-- here email is verified -->
            <div v-if="authLoadError">
              <p  class="subheading font-weight-regular">
                Houve um erro ao carregar informações de autenticação. Por favor, tente novamente mais tarde.
              </p>
            </div>
            <div v-else-if="authLoading">
              <p  class="subheading font-weight-regular">
                Carregando informações de autenticação...
              </p>
            </div>
            <div v-else>
              <!-- auth info was loaded -->
              <p  class="subheading font-weight-regular">
                Informações de autenticação carregadas...
              </p>
            </div>
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
    loading: true,
    errored: false,
    isEmailVerified: null,

    authLoading: true,
    authInfo: null,
    authLoadError: false,

    authChecking: true,
    authValid: null,
    authCheckError: false
  }),

  created() {
    axios.defaults.headers.common = {'Authorization': `Bearer ${this.loginInfo.access_token}`};
  },

  mounted() {
    axios
      .get('/isemailverified')
      .then(response => {
        this.isEmailVerified = response.data.result;
        if (this.isEmailVerified) {
          axios
            .get('/getmyspotifyauth')
            .then( response => {
              this.authInfo = response.data;
              console.log(this.authInfo);
            })
            .catch(error => {
              this.authLoadError = true;
              console.log(error);
            })
            .finally(() => this.authLoading = false);
        }
      })
      .catch(error => {
        console.log(error);
        this.errored = true;
      })
      .finally(() => this.loading = false);
  }
}
</script>