<template>
    <v-container class="fill-height" fluid >
    <v-row align="center" justify="center" >
        <v-col cols="12" sm="8" md="4" >
        <v-card class="elevation-12" >
            <v-toolbar color="primary" dark flat >
            <v-toolbar-title>Recommender Effects</v-toolbar-title>
            </v-toolbar>
            <v-card-text v-if="changeSending">
              <div>Enviando...</div>
            </v-card-text>
            <v-card-text v-else-if="changeSendError">
              <div>Não foi possível mudar a senha.</div>
            </v-card-text>
            <v-card-text v-else-if="changeSentOk">
              <div>Senha alterada com sucesso.</div>
            </v-card-text>
            <v-card-text v-else>
            <v-form v-on:submit.prevent v-model="valid" :lazy-validation="lazy" ref="form">
                <v-text-field
                id="password"
                label="Nova senha"
                v-model="password"
                :rules="passwordRules"
                prepend-icon="lock"
                type="password"
                required
                />
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
            </v-form>
            </v-card-text>
            <v-card-actions v-if="!changeSending">
            <v-spacer />
            <v-btn color="primary" @click="close"><span v-if="!changeSentOk">Cancelar</span><span v-else>Voltar</span></v-btn>
            <v-btn v-if="!changeSentOk && !changeSendError" @click="sendChangePass" :disabled="!valid" color="primary">Enviar</v-btn>
            </v-card-actions>
        </v-card>
        </v-col>
    </v-row>
    </v-container>    
</template>
<script>
import { bus } from "../main";
import axios from "axios";

export default {
    name: "ChangePass",

    props: ['email', 'passchangecode'],    

    data: () => ({
        lazy: true,
        valid: true,

        changeSending: false,
        changeSentOk: false,
        changeSendError: false,


        password : '',
        passwordRules : [
        v => !!v || 'Senha obrigatória',
        v => v.length >= 6 || 'A senha deve ter 6 ou mais caracteres',
        v => /\d/.test(v) || 'A senha deve ter pelo menos 1 dígito',
        v => v.match('[a-zA-Z]+') || 'A senha deve ter pelo menos 1 letra'
        ],
        passwordCheck : '',
    }),

    methods: {
        close() {
            bus.$emit('turnOffChangePass');
        },
        passwordsOk(checkPassword) {
            if (!(checkPassword == this.password)) {
                return "As senhas não coincidem";
            }
            return true;
        },
        sendChangePass() {
            if (this.$refs.form.validate()) {
                this.changeSending = true;
                axios.post('/newpass', {
                    email: this.email,
                    passchangecode: this.passchangecode,
                    newpass: this.password
                })
                .then(() => {
                    this.changeSentOk = true;
                })
                .catch((error) => {
                    this.changeSendError = true;
                    console.log(error);
                })
                .finally(() => this.changeSending = false);
            }
        },
        submitIfEnter(event) {
            if (event.key == 'Enter' && this.valid) {
                this.sendChangePass();
            }
        }      
    },
};
</script>