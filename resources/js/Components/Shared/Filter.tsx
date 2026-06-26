import { Input } from '@/Components/Ui/input'
import { Button } from '@/Components/Ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/Components/Ui/select'
import { Search, XCircle } from 'lucide-react'
import { useDebounce } from 'use-debounce'
import { useEffect, useRef, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/Components/Ui/card';
import { router } from '@inertiajs/react'
import { MultiSelect } from '@/Components/Ui/multi-select'
import MultiSelectSearch from './MultiSelectSearch'

type FieldType = 'text' | 'select'

type FilterField = {
    type: FieldType
    placeholder?: string
    options?: { value: string; label: string }[]
}

type MultiSelectFields =
    | {
        type: 'static';
        options: { value: string; label: string }[];
        placeholder?: string;
        searchRoute?: never;
    }
    | {
        type: 'dynamic';
        searchRoute: string;
        placeholder?: string;
        options?: never;
    };


type Props = {
    routeName?: string,
    fullRoute?: string,
    fields: Record<string, FilterField>,
    multiSelectFields?: {
        [key: string]: MultiSelectFields
    }
}

export default function Filter({ routeName = '', fullRoute = '', fields, multiSelectFields = {} }: Props) {
    const allEntries = Object.entries({
        ...(fields || {}),
        ...(multiSelectFields || {})
      });
    const fields1 = Object.keys(fields).reduce((acc, key) => {
        acc[key] = ''
        return acc
    }, {} as Record<string, string>)
    const fields2 = Object.keys(multiSelectFields).reduce((acc, key) => {
        acc[key] = ''
        return acc
    }, {} as Record<string, string>)
    const initial = {...fields1, ...fields2}

    const [filters, setFilters] = useState(initial)
    const [debouncedFilters] = useDebounce(filters, 500)

    const didInitFromURL = useRef(false)

    useEffect(() => {
        const query = new URLSearchParams(window.location.search)
        const updated = { ...initial }
        Object.keys(allEntries).forEach((key) => {
            updated[key] = query.get(key) || ''
        })
        setFilters(updated)
        didInitFromURL.current = true
    }, [])

    const handleReset = () => {
        setFilters(initial)
        router.get(routeName ? route(routeName) : fullRoute, {}, { preserveState: true, preserveScroll: true, replace: true })
    }

    useEffect(() => {
        if (didInitFromURL.current) {
            didInitFromURL.current = false
            return
        }

        // Avoid request if all filters are empty
        if (Object.values(debouncedFilters).every((v) => !v)) return

        const filledFilters = Object.entries(debouncedFilters).reduce((acc, [key, value]) => {
            if (value) {
                acc[key] = value
            }
            return acc
        }, {} as Record<string, string>)

        router.get(routeName ? route(routeName) : fullRoute, filledFilters, {
            preserveState: true,
            preserveScroll: true,
            replace: true,
        })
    }, [debouncedFilters])

    return (
        <Card className="mb-6">
            <CardHeader className='flex justify-between items-center'>
                <Button onClick={handleReset} variant="outline" className='self-end'>
                    <XCircle className="mr-2 h-4 w-4" />
                    حذف الفلاتر
                </Button>
            </CardHeader>
            <CardContent>
                <div className="flex flex-wrap gap-4 mb-6">
                    {Object.entries({...fields, ...multiSelectFields}).map(([name, field]) => {
                        if (field.type === 'text') {
                            return (
                                <div key={name} className="relative w-full">
                                    <Input
                                        value={filters[name] || ''}
                                        onChange={(e) => setFilters((prev) => ({ ...prev, [name]: e.target.value }))}
                                        placeholder={field.placeholder}
                                        className="ps-10 w-full"
                                    />
                                    <Search className="absolute start-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                                </div>
                            )
                        }

                        if (field.type === 'select') {
                            return (
                                <Select
                                    key={name}
                                    value={filters[name]}
                                    onValueChange={(value) => setFilters((prev) => ({ ...prev, [name]: value }))}
                                >
                                    <SelectTrigger className="min-w-[200px]">
                                        <SelectValue placeholder={field.placeholder} />
                                    </SelectTrigger>
                                    <SelectContent>
                                        {field.options?.map((opt) => (
                                            <SelectItem key={opt.value} value={opt.value}>
                                                {opt.label}
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            )
                        }

                        return null
                    })}

                    {Object.entries(multiSelectFields).map(([name, field]) =>{ 
                        return  (
                        <MultiSelectSearch
                            key={name}
                            name={name}
                            setFilters={setFilters}
                            type={field.type}
                            searchRoute={field.searchRoute}
                            options={field.options}
                            placeholder={field.placeholder}
                            selectedItems={filters[name]}
                        />
                    )})}
                </div>
            </CardContent>
        </Card>

    )
}
