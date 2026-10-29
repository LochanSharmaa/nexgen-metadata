import React, { useState, useMemo } from "react";
import { FIELD_DEFINITIONS, FieldDefinition } from "../types";

interface FieldSelectorProps {
  selectedFields: Set<string>;
  onToggle: (key: string) => void;
  onSelectCategory: (category: string, selected: boolean) => void;
}

export const FieldSelector: React.FC<FieldSelectorProps> = ({
  selectedFields,
  onToggle,
  onSelectCategory,
}) => {
  const [activeCategory, setActiveCategory] = useState<string>("File System");
  const [search, setSearch] = useState<string>("");

  const categories = useMemo(() => {
    const cats = new Set<string>();
    FIELD_DEFINITIONS.forEach((f) => cats.add(f.category));
    return Array.from(cats);
  }, []);

  const filteredFields = useMemo(() => {
    return FIELD_DEFINITIONS.filter((f) => {
      if (search.trim()) {
        const q = search.toLowerCase();
        return (
          f.label.toLowerCase().includes(q) ||
          f.key.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q)
        );
      }
      return f.category === activeCategory;
    });
  }, [activeCategory, search]);

  return (
    <div className="flex flex-col h-full bg-white/70 backdrop-blur-md rounded-xl border border-purple-100 shadow-sm overflow-hidden">
      {/* Category Tabs & Search Bar */}
      <div className="p-3 border-b border-purple-100 bg-purple-50/50 flex flex-wrap gap-2 items-center justify-between">
        <div className="flex gap-1 overflow-x-auto py-1">
          {categories.map((cat) => {
            const count = FIELD_DEFINITIONS.filter(
              (f) => f.category === cat && selectedFields.has(f.key)
            ).length;
            const isActive = activeCategory === cat && !search;
            return (
              <button
                key={cat}
                onClick={() => {
                  setActiveCategory(cat);
                  setSearch("");
                }}
                className={`px-3 py-1 text-xs font-semibold rounded-lg transition-all ${
                  isActive
                    ? "bg-[#630ed4] text-white shadow-sm"
                    : "bg-white text-gray-700 hover:bg-purple-100"
                }`}
              >
                {cat} ({count})
              </button>
            );
          })}
        </div>
        <input
          type="text"
          placeholder="Search 200+ fields..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="text-xs px-3 py-1.5 rounded-lg border border-purple-200 focus:outline-none focus:ring-1 focus:ring-[#630ed4] bg-white w-48"
        />
      </div>

      {/* Action Header */}
      {!search && (
        <div className="px-4 py-2 bg-purple-50/30 border-b border-purple-100 flex justify-between items-center text-xs">
          <span className="font-semibold text-gray-700">{activeCategory}</span>
          <div className="space-x-2">
            <button
              onClick={() => onSelectCategory(activeCategory, true)}
              className="text-[#630ed4] hover:underline font-medium"
            >
              Select All
            </button>
            <span>•</span>
            <button
              onClick={() => onSelectCategory(activeCategory, false)}
              className="text-gray-500 hover:underline font-medium"
            >
              Clear
            </button>
          </div>
        </div>
      )}

      {/* Checkbox Grid */}
      <div className="p-4 overflow-y-auto grid grid-cols-2 gap-2 flex-1">
        {filteredFields.map((field) => {
          const checked = selectedFields.has(field.key);
          return (
            <label
              key={field.key}
              title={field.description}
              className={`flex items-start p-2 rounded-lg border text-xs cursor-pointer select-none transition-all ${
                checked
                  ? "bg-purple-50/70 border-purple-300 shadow-sm"
                  : "bg-white border-gray-200 hover:border-purple-200"
              }`}
            >
              <input
                type="checkbox"
                checked={checked}
                onChange={() => onToggle(field.key)}
                className="mt-0.5 rounded text-[#630ed4] focus:ring-[#630ed4] mr-2"
              />
              <div className="flex-1 overflow-hidden">
                <div className="font-semibold text-gray-800 truncate">
                  {field.label}
                </div>
                <div className="text-[10px] text-gray-500 truncate">
                  {field.description}
                </div>
              </div>
            </label>
          );
        })}
      </div>
    </div>
  );
};
