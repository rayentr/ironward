<!-- Vue v-html rendering untrusted HTML — XSS. -->

<template>
  <section>
    <h2>{{ title }}</h2>
    <div v-html="rawHtmlFromUser"></div>
  </section>
</template>

<script setup>
import { ref, onMounted } from "vue";
const rawHtmlFromUser = ref("");
onMounted(async () => {
  const res = await fetch("/api/profile/bio");
  rawHtmlFromUser.value = await res.text();
});
</script>
