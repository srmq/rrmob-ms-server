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
              <div v-if="authChecking">
                Checando informações de autenticação...
              </div>
              <div v-else-if="authCheckError">
                Erro ao checar autenticação com Spotify. Por favor tente novamente mais tarde.
              </div>
              <div v-else-if="authValid">
                Obrigado! Você já está participando do nosso experimento. Aguarde novidades!
              </div>
              <div v-else>
                <div v-if="authUrlLoading">
                  {{authUrlMessage()}}
                </div>
                <div v-else-if="authUrlErrored">
                  Erro ao carregar URL de autenticação. Por favor tente novamente mais tarde...
                </div>
                <div v-else>
                  Por favor, acesse <a v-bind:href="authUrl">este link</a> para conceder autorização ao Recommender Effects para acessar suas informações no Spotify. 
                  Os dados acessados serão utilizados exclusivamente no contexto do experimento.
                </div>
              </div>
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
    authAccessToken: null,
    authLoadError: false,

    authChecking: true,
    authValid: false,
    authCheckError: false,

    authUrlLoading: true,
    authUrlErrored: false,
    authUrl: ''
  }),

  methods: {
    verifySpotifyAuth() {
      if (this.authAccessToken == null) {
        this.authChecking = false;
        this.authValid = false;
        this.authCheckError = false;
      } else {
        this.authChecking = true;
        const myAxios = axios.create({
          headers: {
            common: {
              'Authorization': 'Bearer ' + this.authAccessToken
            }
          }
        });
        myAxios.get('https://api.spotify.com/v1/me')
        .then(response => {
          if(response.data && ('email' in response.data)) {
            this.authValid = true;
          } else {
            this.authValid = false;
          }
          console.log(response.data);
        })
        .catch(error => {
          this.authCheckError = true;
          console.log(error);
        })
        .finally(() => this.authChecking = false);
      }
    },
    getMySpotifyAuth() {
      axios
        .get('/getmyspotifyaccesstoken')
        .then( response => {
          if ('access_token' in response.data) {
            this.authAccessToken = response.data.access_token;
          }
          
          console.log(response);
          this.verifySpotifyAuth();
        })
        .catch(error => {
          this.authLoadError = true;
          console.log(error);
        })
        .finally(() => this.authLoading = false);
    },
    authUrlMessage() {
      axios
        .get('/spotauthorize')
        .then( response => {
          if ('url' in response.data) {
            this.authUrl = response.data.url;
          }
        })
        .catch(error => {
          this.authUrlErrored = true;
          console.log(error);
        })
        .finally(() => this.authUrlLoading = false);
      return 'Carregando URL de autenticação...';
    }
  },

  created() {
    axios.defaults.headers.common = {'Authorization': `Bearer ${this.loginInfo.access_token}`};
  },

  mounted() {
    axios
      .get('/isemailverified')
      .then(response => {
        this.isEmailVerified = response.data.result;
        if (this.isEmailVerified) {
          this.getMySpotifyAuth();
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