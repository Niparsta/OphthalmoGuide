<script setup lang="ts">
defineProps<{
  title: string
  message: string
  confirmText?: string
}>()

const emit = defineEmits<{
  cancel: []
  confirm: []
}>()
</script>

<template>
  <div class="confirm-modal-overlay" @click.self="emit('cancel')">
    <div class="confirm-modal-card" role="dialog" aria-modal="true" :aria-label="title">
      <h3>{{ title }}</h3>
      <p>{{ message }}</p>
      <div class="modal-buttons">
        <button type="button" class="btn-modal-cancel" @click="emit('cancel')">Отмена</button>
        <button type="button" class="btn-modal-confirm" @click="emit('confirm')">
          {{ confirmText || 'Подтвердить' }}
        </button>
      </div>
    </div>
  </div>
</template>
