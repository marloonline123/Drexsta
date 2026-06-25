import { useForm } from '@inertiajs/react'
import React from 'react'

interface IsActiveTogglarProps {
    route: string;
    children: React.ReactElement
}

export default function IsActiveTogglar({route, children}: IsActiveTogglarProps) {
    const { patch } = useForm();

    const handleToggle = () => {
        patch(route, {
            preserveScroll: true
        })
    } 
  return (
    <div onClick={handleToggle} className='cursor-pointer'>
        {children}
    </div>
  )
}
