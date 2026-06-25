import { PaginationMeta } from '@/Types/global';
import React from 'react';
import Pagination from './Pagination';

interface ResourceListProps {
    dataLenght: number;
    filled: React.ReactNode;
    empty: React.ReactNode;
    paginationData?: PaginationMeta;
}
export default function ResourceList({ dataLenght, filled, empty, paginationData }: ResourceListProps) {
    return (
        <div>
            {dataLenght === 0 ? empty : filled}

            {/* Pagination */}
            {paginationData && <Pagination meta={paginationData} />}
        </div>
    );
}
