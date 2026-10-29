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
      className="flex items-center justify-between p-2 mb-1 bg-white border border-purple-100 rounded-lg text-xs shadow-sm hover:border-purple-300 select-none group"
    >
      <div className="flex items-center space-x-2">
        <span
          {...attributes}
          {...listeners}
          className="cursor-grab text-gray-400 group-hover:text-purple-600 font-bold px-1"
        >
          ⠿
        </span>
        <span className="text-gray-400 font-mono text-[10px] w-4">{index + 1}.</span>
        <span className="font-semibold text-gray-700">{label}</span>
      </div>
      <button
        onClick={() => onRemove(id)}
        className="text-gray-400 hover:text-red-500 font-bold px-1"
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
    <div className="flex flex-col h-full bg-white/70 backdrop-blur-md rounded-xl border border-purple-100 shadow-sm overflow-hidden">
      <div className="p-3 border-b border-purple-100 bg-purple-50/50 flex justify-between items-center">
        <div>
          <span className="font-bold text-xs text-gray-800">Column Sequence</span>
          <span className="ml-2 px-1.5 py-0.5 text-[10px] bg-[#630ed4] text-white rounded-full font-bold">
            {columns.length}
          </span>
        </div>
        <button
          onClick={onReset}
          className="text-xs text-gray-500 hover:text-[#630ed4] font-medium"
        >
          Reset
        </button>
      </div>

      <div className="p-3 overflow-y-auto flex-1">
        {columns.length === 0 ? (
          <div className="text-center text-xs text-gray-400 mt-8">
            No columns selected. Check items in the field selector.
          </div>
        ) : (
          <DndContext
            sensors={sensors}
            collisionDetection={closestCenter}
            onDragEnd={handleDragEnd}
          >
            <SortableContext items={columns} strategy={verticalListSortingStrategy}>
              {columns.map((colKey, index) => (
                <SortableItem
                  key={colKey}
                  id={colKey}
                  index={index}
                  label={getLabel(colKey)}
                  onRemove={onRemove}
                />
              ))}
            </SortableContext>
          </DndContext>
        )}
      </div>
    </div>
  );
};
