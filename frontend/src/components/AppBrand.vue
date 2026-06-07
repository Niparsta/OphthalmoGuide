<script setup lang="ts">
defineProps<{
  subtitle?: string
  danger?: boolean
  clickable?: boolean
}>()

const emit = defineEmits<{
  reset: []
}>()
</script>

<template>
  <div class="brand-group-centered">
    <button
      v-if="clickable"
      type="button"
      class="logo-wrapper-row logo-wrapper-button"
      title="Начать новый анализ (сбросить текст и результаты)"
      aria-label="Начать новый анализ"
      @click="emit('reset')"
    >
      <svg class="blinking-eye-logo" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
        <circle cx="12" cy="12" r="3.5"></circle>
      </svg>
      <h1 class="logo-text">OphthalmoGuide</h1>
    </button>

    <div v-else class="logo-wrapper-row">
      <svg
        class="blinking-eye-logo"
        :style="danger ? 'color: #ff4a4a;' : undefined"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2.5"
        stroke-linecap="round"
        stroke-linejoin="round"
      >
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
        <circle cx="12" cy="12" r="3.5"></circle>
      </svg>
      <h1 class="logo-text">OphthalmoGuide</h1>
    </div>

    <p v-if="subtitle" class="logo-subtitle">{{ subtitle }}</p>
  </div>
</template>
