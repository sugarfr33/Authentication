<script setup lang="ts" generic="T">
// Cells are rendered with text interpolation only (never as raw HTML), so values such as IP addresses and user
// agents can never become markup. When the table is narrower than 30em, rows stack into labelled blocks: no
// horizontal scroll. The stacked layout sets display:block, which makes some browsers drop the implicit table
// semantics (WCAG 1.3.1), so every element carries its table role explicitly.
import { useId } from 'vue';
import type { TableColumn } from './types';

withDefaults(
  defineProps<{
    columns: readonly TableColumn[];
    rows: readonly T[];
    rowKey: (row: T) => string;
    /** Every table has a caption (its accessible name); hide it visually if a heading already says it. */
    caption: string;
    captionHidden?: boolean;
    emptyText?: string;
  }>(),
  { captionHidden: false, emptyText: '' },
);

defineSlots<{
  cell?(props: { row: T; column: TableColumn; value: unknown }): unknown;
  empty?(): unknown;
}>();

function valueOf(row: T, key: string): unknown {
  return typeof row === 'object' && row !== null ? (row as Record<string, unknown>)[key] : undefined;
}

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

function asText(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (value instanceof Date) return dateFormat.format(value);
  return String(value);
}

const captionId = `table-${useId()}-caption`;

function alignClass(column: TableColumn): string {
  return column.align === 'end' ? 'cell--end' : 'cell--start';
}
</script>

<template>
  <div class="table-wrap">
    <table class="table" role="table" :aria-labelledby="captionId">
      <caption :id="captionId" :class="{ 'visually-hidden': captionHidden }">{{ caption }}</caption>
      <thead role="rowgroup">
        <tr role="row">
          <th v-for="column in columns" :key="column.key" scope="col" role="columnheader" :class="alignClass(column)">{{ column.label }}</th>
        </tr>
      </thead>
      <tbody role="rowgroup">
        <tr v-if="rows.length === 0" role="row">
          <td class="table__empty" role="cell" :colspan="columns.length">
            <slot name="empty">{{ emptyText }}</slot>
          </td>
        </tr>
        <tr v-for="row in rows" :key="rowKey(row)" role="row">
          <td v-for="column in columns" :key="column.key" role="cell" :data-label="column.label" :class="alignClass(column)">
            <slot name="cell" :row="row" :column="column" :value="valueOf(row, column.key)">{{
              asText(valueOf(row, column.key))
            }}</slot>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<style scoped>
.table-wrap {
  width: 100%;
  container-type: inline-size;
}

.table {
  width: 100%;
  border-collapse: collapse;
  font-size: var(--font-size-sm);
}

caption {
  padding-bottom: var(--space-2);
  text-align: start;
  font-weight: var(--font-weight-semibold);
  font-size: var(--font-size-md);
}

th,
td {
  padding: var(--table-cell-padding-y) var(--table-cell-padding-x);
  border-bottom: var(--border-width) solid var(--color-border);
  vertical-align: top;
}

th {
  background: var(--color-surface-sunken);
  color: var(--color-text);
  font-weight: var(--font-weight-semibold);
}

.cell--start {
  text-align: start;
}

.cell--end {
  text-align: end;
}

.table__empty {
  color: var(--color-text-muted);
  text-align: center;
}

@container (max-width: 30em) {
  thead {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
  }

  .table,
  tbody,
  tr,
  td {
    display: block;
    width: 100%;
  }

  tr {
    padding: var(--space-2) 0;
    border-bottom: var(--border-width) solid var(--color-border);
  }

  td {
    display: grid;
    grid-template-columns: minmax(6rem, 35%) 1fr;
    gap: var(--space-2);
    padding: var(--space-1) 0;
    border-bottom: 0;
    text-align: start;
  }

  td::before {
    content: attr(data-label);
    /* visual label only: the column header already names the cell for assistive tech */
    content: attr(data-label) / '';
    color: var(--color-text-muted);
    font-weight: var(--font-weight-medium);
  }

  .table__empty {
    display: block;
  }

  .table__empty::before {
    content: none;
  }
}
</style>
