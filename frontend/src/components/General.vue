<template>
    <div class="container">
      <h1>General</h1>
      <div class="hide-secrets" @click="hideSecrets=!hideSecrets">
          <input type="checkbox" v-model="hideSecrets">Hide Passwords</input>
      </div>
      <hr>
      <div class="tableFixHead">
        <div class="buttons">
          <h3>SAM password reuse</h3>
          <div class="functionalities-buttons">
            <button style="margin-left: 2rem;" @click="exportSamReuseToCsv();" type="button" title="Export SAM Reused accounts to csv" class="btn btn-sm">Export SAM Reuse</button>
          </div>
        </div>
        <table style="width: 90%;" class="table table-hover">
          <thead>
            <tr>
              <th class="text_column" scope="col">
                  Computer
              </th>
              <th class="text_column" scope="col">
                  RID
              </th>
              <th class="text_column" scope="col">
                  Windows User
              </th>
              <th class="text_column" scope="col">
                  LM Hash
              </th>
              <th class="text_column" scope="col">
                  NT Hash
              </th>
            </tr>
          </thead>
          <tbody class="sam-reuse" v-for="(samReuseTable, index) in samHashes" :key="index">
            <tr :class="{ rid500: samReuse.rid == 500 }" v-for="(samReuse, index) in samReuseTable" :key="index">
              <td @click="copyItemToClipBoard(samReuse.hostname)">{{ samReuse.hostname }}</td>
              <td @click="copyItemToClipBoard(samReuse.rid)">{{ samReuse.rid }}</td>
              <td @click="copyItemToClipBoard(samReuse.username)">{{ samReuse.username }}</td>
              <td @click="copyItemToClipBoard(samReuse.lmhash)">{{ hideSecretsOnRender(samReuse.lmhash) }}</td>
              <td @click="copyItemToClipBoard(samReuse.nthash)">{{ hideSecretsOnRender(samReuse.nthash) }}</td>
            </tr>
          </tbody>
        </table>
        <br><br>
        <div class="buttons">
          <h3>Scheduled Tasks</h3>
          <div class="functionalities-buttons">
            <button style="margin-left: 2rem;" @click="exportSCTasksToCsv();" type="button" title="Export Scheduled Tasks to csv" class="btn btn-sm">Export Scheduled Tasks</button>
          </div>
        </div>
        
        <br><br>
        <table style="width: 90%;" class="table table-hover">
          <thead>
            <tr>
              <th class="text_column" scope="col">
                  Computer
              </th>
              <th class="text_column" scope="col">
                  Target
              </th>
              <th class="text_column" scope="col">
                  Username
              </th>
              <th class="text_column" scope="col">
                  Password
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(scheduledTask, index) in scheduledTasks" :key="index">
              <td @click="copyItemToClipBoard(scheduledTask.hostname)">{{ scheduledTask.hostname }}</td>
              <td @click="copyItemToClipBoard(scheduledTask.target)">{{ scheduledTask.target }}</td>
              <td @click="copyItemToClipBoard(scheduledTask.username)">{{ scheduledTask.username }}</td>
              <td @click="copyItemToClipBoard(scheduledTask.password)">
                <span v-if="scheduledTask.password != null" class="fullValue" @mouseover="showFullSCTasksAccounts[index] = true" @mouseleave="showFullSCTasksAccounts[index] = false">
                  {{ scheduledTask.password.length > 20 ? hideSecretsOnRender(scheduledTask.password).substring(0,20)+".." : hideSecretsOnRender(scheduledTask.password) }}
                  <div :id="'sc_' + index" v-show="showFullSCTasksAccounts[index]">
                    {{scheduledTask.password}}
                  </div>
                </span>
              </td>
            </tr>
          </tbody>
        </table>
        <br><br>
        <div class="buttons">
          <h3>Service accounts (in LSA secrets)</h3>
          <div class="functionalities-buttons">
            <button style="margin-left: 2rem;" @click="exportLSAToCsv();" type="button" title="Export Service accounts to csv" class="btn btn-sm">Export Service Accounts</button>
          </div>
        </div>
        <br><br>
        <table style="width: 90%;" class="table table-hover">
          <thead>
            <tr>
              <th class="text_column" scope="col">
                  Computer
              </th>
              <th class="text_column" scope="col">
                  Username
              </th>
              <th class="text_column" scope="col">
                  Password
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(serviceAccount, index) in serviceAccounts" :key="index">
              <td @click="copyItemToClipBoard(serviceAccount.hostname)">{{ serviceAccount.hostname }}</td>
              <td @click="copyItemToClipBoard(serviceAccount.username)">{{ serviceAccount.username }}</td>
              <td @click="copyItemToClipBoard(serviceAccount.password)">
                <span v-if="serviceAccount.password != null" class="fullValue" @mouseover="showFullServiceAccounts[index] = true" @mouseleave="showFullServiceAccounts[index] = false">
                  {{ serviceAccount.password.length > 20 ? hideSecretsOnRender(serviceAccount.password).substring(0,20)+".." : hideSecretsOnRender(serviceAccount.password) }}
                  <div :id="'sa_' + index" v-show="showFullServiceAccounts[index]">
                    {{serviceAccount.password}}
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
import { copyToClipBoard, arrayToCsv, downloadBlob } from '../utils';

export default {
  data() {
    return {
      samHashes: [],
      scheduledTasks: [],
      serviceAccounts: [],
      hideSecrets: false,
      showFullServiceAccounts: [],
      showFullSCTasksAccounts: [],
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
    exportSamReuseToCsv(){
      console.log('Export SAM Reuse to CSV');
      var samReuseUnified = []
      this.samHashes.forEach(samReuseTable =>  samReuseTable.forEach(samReuseElement => samReuseUnified.push(samReuseElement)));
      const dataToExport = arrayToCsv(samReuseUnified);
      downloadBlob(dataToExport, 'sam_reuse_export_' + Date.now()  + '.csv');
    },
    exportSCTasksToCsv(){
      console.log('Export Scheduled Tasks to CSV');
      // this.scheduledTasks.forEach(element =>  samReuseUnified.push(samReuseElement));
      // console.log(samReuseUnified)
      const dataToExport = arrayToCsv(this.scheduledTasks);
      downloadBlob(dataToExport, 'scheduledtasks_export_' + Date.now()  + '.csv');
    },
    exportLSAToCsv(){
      console.log('Export Service Accounts to CSV');
      // this.scheduledTasks.forEach(element =>  samReuseUnified.push(samReuseElement));
      // console.log(samReuseUnified)
      const dataToExport = arrayToCsv(this.serviceAccounts);
      downloadBlob(dataToExport, 'serviceaccounts_export_' + Date.now()  + '.csv');
    },
    getGeneralInfo() {
      var samReusePath = config.apiPath + '/api/sam_reuse';
      var scheduledTaskPath = config.apiPath + '/api/scheduled_tasks';
      var serviceAccountsPath = config.apiPath + '/api/lsa_secrets';
      axios.get(samReusePath)
        .then((res) => {
          this.samHashes = res.data;
        })
        .catch((error) => {
            console.error(error);
        });
      axios.get(scheduledTaskPath)
        .then((res) => {
          this.scheduledTasks = res.data;
        })
        .catch((error) => {
            console.error(error);
        });
      axios.get(serviceAccountsPath)
        .then((res) => {
          this.serviceAccounts = res.data;
        })
        .catch((error) => {
            console.error(error);
        });
      this.showFullServiceAccounts[0] = false;
      this.showFullSCTasksAccounts[0] = false;
    },
  },
  created() {
    this.getGeneralInfo();
  }
};
</script>
  
<style lang="scss">
  
  .text_column {
    min-width:10rem;
    max-width:10rem;
  }

  tr {
    border-color: #ddd !important;
  }

  .buttons {
    height: 5rem;
  }

  .rid500 {
      color: var(--primary);
      font-weight: bold;
  }

  tbody.sam-reuse { z-index: 1;border-top: solid 0.2rem; }
  tbody.sam-reuse:last-child { z-index: 1;border-top: solid 0.2rem; border-bottom: solid 0.2rem;  }
</style>