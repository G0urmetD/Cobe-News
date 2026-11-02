import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { api } from "@/lib/api"
import { errorText } from "@/lib/errors"

/** Load + save one settings section (GET/PUT /api/admin/settings/{section}). */
export function useSection<T extends object>(section: string) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const query = useQuery({ queryKey: ["settings", section], queryFn: () => api.get<T>(`/api/admin/settings/${section}`) })
  const save = useMutation({
    mutationFn: (value: T) => api.put<T>(`/api/admin/settings/${section}`, value),
    onSuccess: (data) => {
      qc.setQueryData(["settings", section], data)
      toast.success(t("common.saved"))
    },
    onError: (e) => toast.error(errorText(t, e)),
  })
  return { data: query.data, isLoading: query.isLoading, error: query.error, refetch: query.refetch, save }
}
