<template>
  <div class="container">
    <h1>Secrets</h1>
    <div class="hide-secrets" @click="hideSecrets=!hideSecrets">
      <input type="checkbox" v-model="hideSecrets">Hide Passwords</input>
    </div>
    <hr><br><br>
    <div class="buttons">
      <div class="functionalities-buttons">
        <button style="margin-left: 1rem;" @click="exportSecretsToCsv();" type="button" title="Export checked items to csv" class="btn btn-sm">Export</button>
      </div>
      <div class="page-selection">
        <div class="page-size-selection">
          Page size:
          <input type="number" min="1" v-model="page_size" @input="getSecrets();">
        </div>
        <div class="page-number-selection">
          <input type="number" min="1" v-model="page_number" @input="getSecrets();"> / {{ page_max }}
        </div>            
      </div>
    </div>
    <p style="font-style: italic">Note: Click on a value in a cell to copy it to clipboard. <b>Search</b> button will show searchbar for every column.</p>
    <br><br>
    <div class="tableFixHead">
      <table class="table table-hover">
        <thead>
          <tr>
            <th scope="col"><input id="main-checkbox" type="checkbox" @click="toggleSecretsSelection" :checked="allChecked"></th>
            <th scope="col">
              <span>
                Computer
                <div>
                  <input type="text" placeholder="Search text" v-model="computer_search_value" @input="resetPageInfo(); getSecrets();">
                </div>
              </span>
            </th>
            <th scope="col">
              <span>
                Windows User
                <div>
                  <input type="text" placeholder="Search text" v-model="windows_user_search_value" @input="resetPageInfo(); getSecrets();">
                </div>
              </span>
            </th>
            <th scope="col">
              <span>
                Program
                <div>
                  <select style="width: 10rem;" v-model="program_search_value" @change="resetPageInfo(); getSecrets();">
                    <option selected="true" value=""></option>
                    <option v-for="program in programsList" :value="program">
                      {{ program }}
                    </option>
                  </select>
                  <!-- <input type="text" placeholder="Search text" v-model="program_search_value" @input="resetPageInfo(); getSecrets();"> -->
                </div>
              </span>
            </th>
            <th scope="col">
              <span>
                Target
                <div>
                  <input type="text" placeholder="Search text" v-model="target_search_value" @input="resetPageInfo(); getSecrets();">
                </div>
              </span>
            </th>
            <th scope="col">
              <span>
                Username
                <div>
                  <input type="text" placeholder="Search text" v-model="username_search_value" @input="resetPageInfo(); getSecrets();">
                </div>
              </span>
            </th>
            <th scope="col">
              <span>
                Password
                <div>
                  <input type="text" placeholder="Search text" v-model="password_search_value" @input="resetPageInfo(); getSecrets();">
                </div>
              </span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(secret, index) in secrets" :key="index">
            <td><input class="item-checkbox" :id="index" type="checkbox" @click="clickSecretsCheckbox"></td>
            <td style="cursor: pointer;" @click="copyItemToClipBoard(secret.hostname)">{{ secret.hostname }}</td>
            <td style="cursor: pointer;" @click="copyItemToClipBoard(secret.windows_user)">{{ secret.windows_user }}</td>
            <td style="cursor: pointer;" @click="copyItemToClipBoard(secret.program)">{{ secret.program }}</td>
            <td style="cursor: pointer;" @click="copyItemToClipBoard(secret.target)">
              <span v-if="secret.target != null" class="fullValue" @mouseover="showFullTarget[index] = true" @mouseleave="showFullTarget[index] = false">
                {{ secret.target.length > 20 ? secret.target.substring(0,20)+".." : secret.target }}
                <div :id="'target_' + index" v-show="showFullTarget[index]">
                  {{secret.target}}
                </div>
              </span>
            </td>
            <td style="cursor: pointer;" @click="copyItemToClipBoard(secret.username)">
              <span v-if="secret.username != null" class="fullValue" @mouseover="showFullUsername[index] = true" @mouseleave="showFullUsername[index] = false">
                {{ secret.username.length > 20 ? secret.username.substring(0,20)+".." : secret.username }}
                <div :id="'username_' + index" v-show="showFullUsername[index]">
                  {{secret.username}}
                </div>
              </span>
            </td>
            <td style="cursor: pointer;" @click="copyItemToClipBoard(secret.password)">
              <span v-if="secret.password != null" class="fullValue" @mouseover="showFullPassword[index] = true" @mouseleave="showFullPassword[index] = false">
                {{ secret.password.length > 20 ? hideSecretsOnRender(secret.password).substring(0,20)+".." : hideSecretsOnRender(secret.password) }}
                <div :id="'password_' + index" v-show="showFullPassword[index]">
                  {{secret.password}}
                </div>
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script>
import axios from 'axios';
import {config} from '../config';
import { 
  copyToClipBoard, 
  arrayToCsv, 
  downloadBlob,
  clickCheckbox,
  toggleSelection,
} from '../utils';


export default {
  data() {
    return {
      secrets: [],
      programsList: [],
      showFullUsername: [],
      showFullPassword: [],
      showFullTarget: [],
      page_size: 100,
      page_max: 1,
      page_number: 1,
      search_boxes: false,
      computer_search_value: '',
      windows_user_search_value: '',
      collector_search_value: '',
      program_search_value: '',
      target_search_value: '',
      username_search_value: '',
      password_search_value: '',
      allChecked: false,
      hideSecrets: false,
    };
  },
  methods: {
    hideSecretsOnRender(data){
      if (this.hideSecrets) {
        return data.replace(/./g, "*")
      }
      return data
    },
    copyItemToClipBoard(data){
      copyToClipBoard(this, data);
    },
    resetPageInfo() {
      this.page_number = 1;
    },
    clickSecretsCheckbox(){
      clickCheckbox(this);
    },
    toggleSecretsSelection(){
      toggleSelection(this);
    },
    exportSecretsToCsv(){
      console.log('Export secrets to CSV');
      var secretsCheckboxes = document.getElementsByClassName("item-checkbox");
      var secretsToExport = [];
      for (var i=0; i<secretsCheckboxes.length; i++) {
        if (secretsCheckboxes[i].checked) {
          secretsToExport.push(this.secrets[i]);
        }
      }
      const dataToExport = arrayToCsv(secretsToExport)
      downloadBlob(dataToExport, 'secret_export_' + Date.now()  + '.csv');
    },
    getSecrets() {
      var path = config.apiPath + '/api/secrets?';
      path += 'page=' + (this.page_number -1) + '&';
      path += 'page_size=' + this.page_size + '&';
      path += 'computer_hostname=' + this.computer_search_value + '&';
      path += 'collector=' + this.collector_search_value + '&';
      path += 'program=' + this.program_search_value + '&';
      path += 'target=' + this.target_search_value + '&';
      path += 'username=' + this.username_search_value + '&';
      path += 'password=' + this.password_search_value + '&';
      path += 'windows_user=' + this.windows_user_search_value + '&';
      axios.get(path)
        .then((res) => {
          this.secrets = res.data.secrets;
          this.programsList = res.data.programs_list
          this.itemsLen = this.secrets.length;
          console.log("w")
          console.log(res.data.count)
          console.log(this.page_size)
          this.page_max = Math.ceil(res.data.count/this.page_size); 
          this.showFullUsername[0] = false; //need to init
          this.showFullPassword[0] = false; //need to init
        })
        .catch((error) => {
            console.error(error);
        });1
    },
  },
  created() {
    this.getSecrets();
  }
};

</script>