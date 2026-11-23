<script setup lang="ts">
import catalog from '../data/claude-code-domains.json'
const count = catalog.groups.reduce((sum, group) => sum + group.domains.length, 0)
</script>

<template>
  <details class="panel detail-panel domain-reference">
    <summary>Claude Code 候选域名（{{ count }} 个）</summary>
    <p class="muted-copy">来源：{{ catalog.sourceDocument }} · {{ catalog.extractedOn }}。这是参考清单，未记录客户端实际访问。第三方域名也可能被其他应用使用。</p>
    <div class="domain-groups">
      <div v-for="group in catalog.groups" :key="group.name">
        <h4>{{ group.name }}</h4>
        <ul><li v-for="domain in group.domains" :key="domain"><code>{{ domain }}</code></li></ul>
      </div>
    </div>
    <p class="muted-copy">固定出口要求适用于受管应用的所有目标，包括清单以外的域名和直接使用 IP 地址的连接。</p>
  </details>
</template>

<style scoped>
summary { cursor: pointer; font-weight: 600; }
.domain-reference p { margin-top: 14px; }
.domain-groups { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 260px), 1fr)); gap: 18px; margin-top: 18px; }
ul { margin: 6px 0 0; padding-left: 18px; line-height: 1.65; }
code { overflow-wrap: anywhere; }
</style>
