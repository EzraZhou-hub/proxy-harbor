<script setup lang="ts">
withDefaults(defineProps<{ name: string; size?: number }>(), { size: 20 })
const paths: Record<string, string> = {
 grid: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
 apps: 'M4 4h16v12H4z M8 20h8 M12 16v4',
 proxy: 'M4 5h16v5H4z M4 14h16v5H4z M7 7.5h.01 M7 16.5h.01 M16 7.5h2 M16 16.5h2',
 activity: 'M3 12h4l3-8 4 16 3-8h4', arrow: 'M5 12h14 M13 6l6 6-6 6',
 plus: 'M12 5v14 M5 12h14', refresh: 'M20 7v5h-5 M4 17v-5h5 M6 7a7 7 0 0 1 12-2l2 3 M4 16l2 3a7 7 0 0 0 12-2',
 folder: 'M3 7V5h6l2 2h10v13H3z', shield: 'M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6z M9 12h6',
 check: 'M5 12l4 4L19 6', close: 'M6 6l12 12 M6 18L18 6', edit: 'M15 4l5 5 M4 20l5-1L21 7l-5-5L4 14z',
 trash: 'M3 6h18 M9 6V3h6v3 M5 6l1 15h12l1-15 M10 10v7 M14 10v7',
 download: 'M12 3v12 M7 10l5 5 5-5 M4 16v5h16v-5',
 info: 'M12 11v6 M12 7h.01 M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0',
 globe: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0 M3 12h18 M12 3c5 5 5 13 0 18-5-5-5-13 0-18',
 lock: 'M7 10V7a5 5 0 0 1 10 0v3 M5 10h14v11H5z M12 14v3',
}
</script>
<template><svg :width="size" :height="size" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path :d="paths[name] || paths.info" /></svg></template>
