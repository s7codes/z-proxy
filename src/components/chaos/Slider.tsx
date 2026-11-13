import { useId } from "react";

interface SliderProps {
  label: string;
  unit: string;
  min: number;
  max: number;
  step: number;
  value: number;
  disabled?: boolean;
  onChange: (value: number) => void;
}

export function Slider({ label, unit, min, max, step, value, disabled = false, onChange }: SliderProps) {
  const id = useId();
  const commit = (raw: string) => {
    const parsed = Number(raw);
    if (Number.isFinite(parsed)) onChange(Math.min(max, Math.max(min, Math.round(parsed / step) * step)));
  };

  return (
    <div className={`grid grid-cols-[52px_1fr_76px] items-center gap-2 ${disabled ? "opacity-40" : ""}`}>
      <label htmlFor={id} className="text-xs text-fg-dim">
        {label}
      </label>
      <input
        id={id}
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        disabled={disabled}
        onChange={(e) => commit(e.target.value)}
      />
      <div className="flex h-5 items-center rounded-xs border border-line bg-bg pr-1.5 focus-within:border-fg-faint">
        <input
          type="number"
          min={min}
          max={max}
          step={step}
          value={value}
          disabled={disabled}
          aria-label={`${label} ${unit}`}
          onChange={(e) => commit(e.target.value)}
          className="num w-full min-w-0 bg-transparent pl-1.5 text-right text-xs text-fg-bright outline-none [appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none"
        />
        <span className="num pl-1 text-2xs text-fg-faint">{unit}</span>
      </div>
    </div>
  );
}
