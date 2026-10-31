import React from "react";
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  DragEndEvent,
} from "@dnd-kit/core";
import {
  arrayMove,
  SortableContext,
  sortableKeyboardCoordinates,
  verticalListSortingStrategy,
  useSortable,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { FIELD_DEFINITIONS } from "../types";

interface ColumnSequencerProps {
  columns: string[];
  onReorder: (newOrder: string[]) => void;
  onRemove: (key: string) => void;
  onReset: () => void;
}

const SortableItem: React.FC<{
  id: string;
  index: number;
  label: string;
  onRemove: (id: string) => void;
}> = ({ id, index, label, onRemove }) => {
  const { attributes, listeners, setNodeRef, transform, transition } =
    useSortable({ id });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
  };

  return (
    <div
      ref={setNodeRef}
      style={style}
      className="flex items-center justify-between p-2 mb-1 bg-white border border-stone-200 rounded-lg text-xs shadow-sm hover:border-amber-300 select-none group"
    >
      <div className="flex items-center space-x-2">
        <span
          {...attributes}
          {...listeners}
          className="cursor-grab text-stone-400 group-hover:text-amber-700 font-bold px-1"
        >
          ⠿
        </span>
        <span className="text-amber-800 font-mono text-[10px] w-4 font-bold">{index + 1}.</span>
        <span className="font-semibold text-stone-800">{label}</span>
      </div>
      <button
        onClick={() => onRemove(id)}
        className="text-stone-400 hover:text-red-500 font-bold px-1"
        title="Remove column"
      >
        ×
      </button>
    </div>
  );
};

export const ColumnSequencer: React.FC<ColumnSequencerProps> = ({
  columns,
  onReorder,
  onRemove,
  onReset,
}) => {
  const sensors = useSensors(
    useSensor(PointerSensor),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates,
    })
  );

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event;
    if (over && active.id !== over.id) {
      const oldIndex = columns.indexOf(String(active.id));
      const newIndex = columns.indexOf(String(over.id));
      onReorder(arrayMove(columns, oldIndex, newIndex));
    }
  };

  const getLabel = (key: string) => {
    const def = FIELD_DEFINITIONS.find((f) => f.key === key);
    return def ? def.label : key;
  };

  return (
    <div className="flex flex-col h-full bg-white/80 backdrop-blur-md rounded-xl border border-amber-200 shadow-sm overflow-hidden">
      <div className="p-3 border-b border-amber-200/60 bg-amber-50/50 flex justify-between items-center">
        <div>
          <h2 className="text-xs font-bold text-stone-800 uppercase tracking-wider">
            Export Column Order
          </h2>
          <span className="text-[10px] text-stone-500">
            Drag handles to re-order exported columns
          </span>
        </div>
        <button
          onClick={onReset}
          className="text-xs text-amber-800 hover:text-amber-950 font-bold hover:underline"
        >
          Reset Order
        </button>
      </div>

      <div className="p-3 overflow-y-auto flex-1">
        {columns.length === 0 ? (
          <div className="flex items-center justify-center h-full text-stone-400 text-xs text-center p-4">
            No columns selected. Check items on the left to include in the sequence.
          </div>
        ) : (
          <DndContext
            sensors={sensors}
            collisionDetection={closestCenter}
            onDragEnd={handleDragEnd}
          >
            <SortableContext
              items={columns}
              strategy={verticalListSortingStrategy}
            >
              {columns.map((col, idx) => (
                <SortableItem
                  key={col}
                  id={col}
                  index={idx}
                  label={getLabel(col)}
                  onRemove={onRemove}
                />
              ))}
            </SortableContext>
          </DndContext>
        )}
      </div>

      <div className="p-2.5 bg-amber-50/40 border-t border-amber-200/50 text-right text-xs">
        <span className="text-stone-500 font-medium">
          Active Columns: <strong className="text-amber-950">{columns.length}</strong>
        </span>
      </div>
    </div>
  );
};
