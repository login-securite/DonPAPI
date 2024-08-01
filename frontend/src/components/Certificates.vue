<template>
  <div class="container">
    <h1>Certificates</h1>
    <hr><br><br>
    <div class="buttons">
      <div class="functionalities-buttons">
        <button style="margin-left: 1rem;" @click="exportCertificatesToCsv();" type="button" title="Export checked items to csv" class="btn btn-sm">Export</button>
      </div>
      <div class="page-selection">
        <div class="page-size-selection">
          Page size:
          <input type="number" min="1" v-model="page_size" @input="getCertificates();">
        </div>
        <div class="page-number-selection">
          <input type="number" min="1" v-model="page_number" @input="getCertificates();"> / {{ page_max }}
        </div>            
      </div>
    </div>
    <p style="font-style: italic">Note: Click on a value in a cell to copy it to your clipboard. Click on <b>Yes</b> cells in "<span style="font-weight: bold; font-style: italic;">Client Auth ?</span>" to issue a <a href="https://github.com/ly4k/Certipy">Certipy</a> auth command to your clipboard. <b>Search</b> button will show searchbar for every column.</p>
    <br><br>
    <div class="tableFixHead">
      <table class="table table-hover">
        <thead>
          <tr>
            <th scope="col"><input id="main-checkbox" type="checkbox" @click="toggleCertificatesSelection" :checked="allChecked"></th>
            <th scope="col">
              <span>
                Computer
                <div>
                  <input type="text" placeholder="Search text" v-model="computer_search_value" @input="resetPageInfo(); getCertificates();">
                </div>
              </span>
            </th>
            <th scope="col">
              <span>
                Windows User
                <div>
                  <input type="text" placeholder="Search text" v-model="windows_user_search_value" @input="resetPageInfo(); getCertificates();">
                </div>
              </span>
            </th>
            <th scope="col">
              <span>
                Username
                <div>
                  <input type="text" placeholder="Search text" v-model="username_search_value" @input="resetPageInfo(); getCertificates();">
                </div>
              </span>
            </th>
            <th scope="col">
              <span>
                Client Auth ?
                <div>
                  <select v-model="client_auth_search_value" @change="resetPageInfo(); getCertificates();">
                    <option selected="true" value=""> </option>
                    <option value="1">Yes</option>
                    <option value="0">No</option>
                  </select>
                </div>
              </span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(certificate, index) in certificates" :key="index">
            <td><input class="item-checkbox" :id="index" type="checkbox" @click="clickCertificatesCheckbox"></td>
            <td style="cursor: pointer;" @click="copyItemToClipBoard(certificate.hostname)">{{ certificate.hostname }}</td>
            <td style="cursor: pointer;" @click="copyItemToClipBoard(certificate.windows_user)">{{ certificate.windows_user }}</td>
            <td style="cursor: pointer;" @click="copyItemToClipBoard(certificate.username)">{{ certificate.username }}</td>
            <td v-if="certificate.client_auth" style="font-weight: bold; cursor: pointer;" @click="copyPfxToCertipyCommand(certificate.pfx_file_path)">Yes</td>
            <td v-else>No</td>
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
      certificates: [],
      page_size: 100,
      page_max: 1,
      page_number: 1,
      search_boxes: false,
      computer_search_value: '',
      windows_user_search_value: '',
      username_search_value: '',
      client_auth_search_value: '',
      allChecked: false,
    };
  },
  methods: {
    copyItemToClipBoard(data){
      copyToClipBoard(this, data);
    },
    clickCertificatesCheckbox(){
      clickCheckbox(this);
    },
    toggleCertificatesSelection(){
      toggleSelection(this);
    },
    exportCertificatesToCsv(){
      console.log('Export certificates to CSV');
      var certificatesCheckboxes = document.getElementsByClassName("item-checkbox");
      var certificatesToExport = [];
      for (var i=0; i<certificatesCheckboxes.length; i++) {
        if (certificatesCheckboxes[i].checked) {
          certificatesToExport.push(this.certificates[i]);
        }
      }
      const dataToExport = arrayToCsv(certificatesToExport)
      downloadBlob(dataToExport, 'certificates_export_' + Date.now()  + '.csv');
    },
    copyPfxToCertipyCommand(pfxFilePath){
      copyToClipBoard(this, 'certipy auth -pfx \"' + pfxFilePath + '\"', "certipy command");
    },
    resetPageInfo() {
      this.page_number = 1;
    },
    getCertificates() {
      var path = config.apiPath + '/api/certificates?';
      path += 'page=' + (this.page_number -1) + '&';
      path += 'page_size=' + this.page_size + '&';
      path += 'computer_hostname=' + this.computer_search_value + '&';
      path += 'client_auth=' + (this.client_auth_search_value == '1' ? 'True' : this.client_auth_search_value == '0' ? 'False' : 'None') + '&';
      path += 'username=' + this.username_search_value + '&';
      path += 'windows_user=' + this.windows_user_search_value + '&';
      axios.get(path)
        .then((res) => {
          this.certificates = res.data.certificates;
          this.page_max = Math.ceil(res.data.count/this.page_size); 
        })
        .catch((error) => {
            console.error(error);
        });
    },
  },
  created() {
    this.getCertificates();
  }
};

</script>