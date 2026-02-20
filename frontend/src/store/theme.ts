import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type Theme = 'midnight' | 'cyber' | 'terminal'

interface ThemeState {
  theme: Theme
  setTheme: (theme: Theme) => void
}

export const useThemeStore = create<ThemeState>()(
  persist(
    (set) => ({
      theme: 'midnight',
      setTheme: (theme) => {
        document.documentElement.setAttribute('data-theme', theme)
        set({ theme })
      },
    }),
    {
      name: 'sploitai-theme',
      onRehydrateStorage: () => (state) => {
        if (state?.theme && state.theme !== 'midnight') {
          document.documentElement.setAttribute('data-theme', state.theme)
        }
      },
    }
  )
)
