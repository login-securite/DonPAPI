<script setup>
import {RouterView} from 'vue-router'
import NavBar from './components/NavBar.vue'
console.log(import.meta.env.DEV)
</script>

<template>
	<div class="app">
		<NavBar/>
		<RouterView/>
	</div>
	<notifications position="bottom right" />
</template>
